# MagicPipes in containers and Kubernetes

The agent runs in a container as `magicpipes agent run`, set up entirely by environment variables:
the tunnels it serves are declared there, and it answers a container's health probes. It still
dials out to the server, like any agent, so nothing in the cluster needs to be reachable from
outside it.

There are two ways to use it:

* **A gateway.** One agent in its own Deployment publishes Services by their names in the cluster
  (`80 --host shop.default.svc.cluster.local`). That's one machine for the whole cluster.
* **A sidecar.** An agent in an app's pod publishes that app at `127.0.0.1`. That's one machine for
  each pod.

## The image

```bash
docker build --target agent -t magicpipes-agent .
```

It's `FROM scratch` with only the static `magicpipes` binary, running as user 65532 with its state in
`/data` (`MAGICPIPES_HOME`). Its entry point is `magicpipes agent run`. It carries the public
certificate authorities it was built with, so it needs no CA bundle. `docker build` without
`--target` still builds the server image.

## Settings

| Variable | |
|---|---|
| `MAGICPIPES_TUNNELS` | The tunnels to serve, one per line, each written as the arguments of `magicpipes add` (below) |
| `MAGICPIPES_TUNNELS_FILE` | The same, in a file: a ConfigMap. Both can be set; together they're the list |
| `MAGICPIPES_HEALTH_LISTEN` | Where to answer probes: `9090` for every interface, or `address:port`. Nothing listens without it |
| `MAGICPIPES_SERVER` and `MAGICPIPES_TOKEN` (or `MAGICPIPES_TOKEN_FILE`) | Enroll at the first start, if the agent hasn't been enrolled yet |
| `MAGICPIPES_CA_CERT` | A PEM file to trust for the server, if its certificate is from a private CA (with enrolling) |
| `MAGICPIPES_AGENT_NAME` | The machine's name when it enrolls (default: the hostname, which is the pod's name) |
| `MAGICPIPES_CONFIG` | Read the machine's identity (`config.json`) from this file instead of `/data/config.json`: a Secret |
| `MAGICPIPES_LOG` | Log filter, such as `info` or `debug`. The log goes to standard error |
| `MAGICPIPES_CONNECTIONS` | Connections to the server, 1 to 8 (default 4) |

`agent run` reads the first four only in the foreground. An agent that `magicpipes add` starts in the
background ignores them, so a declaration left in a shell's environment can't remove anything.

### Declaring tunnels

Each line is what you'd type after `magicpipes add`, and the same rules check it. Lines that are
empty or start with `#` are skipped, and words split as a shell splits them, quotes included.
Each tunnel needs a `--name` or `--hostname`, so it keeps its address when the agent starts again:

```text
# The shop for everyone, its admin pages for the team, and the database for people
# holding team:db, through `magicpipes connect`.
8080 --name shop --public
8081 --name shop-admin --tag team:ops
5432 --tcp --name shop-db --tag team:db
```

At each start the agent:

1. Stops with an error naming the line, if a line is wrong. Kubernetes shows that as a crash loop
   with the message in the log.
2. Removes the tunnels it served before that aren't declared any more, once it reaches the server
   ("Removing a tunnel" below says when it can know them).
3. Adds each declared tunnel, as `magicpipes add` would. While one fails, it tries again, waiting 1
   second, then 2, 4 and so on up to 30. An app that's still starting, or a server that can't be
   reached yet, just takes a few more tries.

After that, the connection keeps them, as it keeps any tunnel. `kubectl exec` into the pod with
`magicpipes list` or `magicpipes status` shows them, and `magicpipes add` changes one until the
next start.

### Probes

With `MAGICPIPES_HEALTH_LISTEN` set, the agent answers plain HTTP:

* `/livez`: 200 while the agent runs.
* `/readyz`: 200 once it's connected to the server and every declared tunnel is registered.
  Without declarations, it's every tunnel the agent has. Until then it answers 503, with what it's
  waiting for:

  ```json
  {"ready":false,"connection":"connected","waiting":[{"tunnel":"shop-admin","error":"local_unreachable"}]}
  ```

The answers carry tunnel names, which are in their public addresses anyway, and error codes.

### The machine's identity

An enrollment token works once, and the identity it gives (`config.json`) has to outlast the pod.
There are two ways to keep it.

**As a Secret** (Kubernetes): enroll once, anywhere, and keep the file.

```bash
export MAGICPIPES_HOME=$(mktemp -d)
magicpipes login --server https://mp.example.com --token mpe_… --name cluster-gateway
kubectl create secret generic magicpipes-agent --from-file=config.json="$MAGICPIPES_HOME/config.json"
rm -r "$MAGICPIPES_HOME"
```

Mount it, and point `MAGICPIPES_CONFIG` at it. `/data` can then be an `emptyDir`. The enrollment
token decides whose machine it is, as it does for any `magicpipes login`: a service agent's, from
an administrator, suits a gateway.

**On a volume** (Docker, or a PersistentVolumeClaim): set `MAGICPIPES_SERVER` and
`MAGICPIPES_TOKEN`. The first start enrolls and keeps the identity in `/data`, and later starts use
it and ignore the token.

### Removing a tunnel

Take its line out, and the agent removes it at its next start, if it remembers serving it: that
takes a volume for `/data`. With an `emptyDir`, a new pod doesn't know what an earlier one served.
Remove the tunnel on its page in the management UI, or with `DELETE /api/v1/tunnels/{id}`, or it
stays registered with nothing serving it.

## A gateway

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: magicpipes-tunnels
data:
  tunnels: |
    # Services in the cluster, by name.
    80 --host shop.default.svc.cluster.local --name shop --public
    3000 --host grafana.monitoring.svc.cluster.local --name grafana --tag team:ops
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: magicpipes-gateway
spec:
  replicas: 1
  # One machine serves from one place at a time (see "Limits").
  strategy:
    type: Recreate
  selector:
    matchLabels: {app: magicpipes-gateway}
  template:
    metadata:
      labels: {app: magicpipes-gateway}
    spec:
      securityContext:
        runAsNonRoot: true
        fsGroup: 65532
      containers:
        - name: agent
          image: registry.example.com/magicpipes-agent:0.1.1
          env:
            - {name: MAGICPIPES_CONFIG, value: /etc/magicpipes/identity/config.json}
            - {name: MAGICPIPES_TUNNELS_FILE, value: /etc/magicpipes/tunnels/tunnels}
            - {name: MAGICPIPES_HEALTH_LISTEN, value: "9090"}
          ports:
            - {name: health, containerPort: 9090}
          readinessProbe:
            httpGet: {path: /readyz, port: health}
            periodSeconds: 5
          livenessProbe:
            httpGet: {path: /livez, port: health}
            periodSeconds: 20
          resources:
            requests: {cpu: 50m, memory: 32Mi}
            limits: {memory: 256Mi}
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: identity, mountPath: /etc/magicpipes/identity, readOnly: true}
            - {name: tunnels, mountPath: /etc/magicpipes/tunnels, readOnly: true}
            - {name: data, mountPath: /data}
      volumes:
        - name: identity
          secret: {secretName: magicpipes-agent, defaultMode: 0440}
        - name: tunnels
          configMap: {name: magicpipes-tunnels}
        - name: data
          emptyDir: {}
```

The agent reaches each Service the way any pod does, so the cluster's network policies apply to it.
To pick up a changed ConfigMap, restart it: `kubectl rollout restart deployment/magicpipes-gateway`.

## A sidecar

The same container, next to the app, with the app at `127.0.0.1`:

```yaml
      containers:
        - name: shop
          image: registry.example.com/shop:1.4
          ports: [{containerPort: 8080}]
        - name: magicpipes
          image: registry.example.com/magicpipes-agent:0.1.1
          env:
            - {name: MAGICPIPES_CONFIG, value: /etc/magicpipes/identity/config.json}
            - {name: MAGICPIPES_TUNNELS, value: "8080 --name shop --public"}
          volumeMounts:
            - {name: identity, mountPath: /etc/magicpipes/identity, readOnly: true}
            - {name: data, mountPath: /data}
```

It doesn't matter which container starts first: the agent tries again until the app answers. A
readiness probe on the sidecar makes the whole pod ready only once the tunnel works. That's right
when MagicPipes is the only way to the app, and wrong when a cluster Service also sends it traffic:
then leave the probe off, or pick a health port the app doesn't use.

## Docker

```bash
docker run -d --name shop-tunnel --network shop-net -v magicpipes-agent:/data \
  -e MAGICPIPES_SERVER=https://mp.example.com -e MAGICPIPES_TOKEN=mpe_… \
  -e MAGICPIPES_TUNNELS="80 --host shop --name shop --public" \
  magicpipes-agent
```

The token is used once, at the first start. After that the volume holds the identity.

## Limits

These are for the next phases of the [roadmap](ROADMAP.md#kubernetes-magicpipes-as-a-clusters-ingress):

* **One machine serves from one place.** Two agents with the same identity take turns, each new
  connection replacing the other's. So a gateway runs one replica, with `strategy: Recreate`, and a
  sidecar's Secret is for one pod. Several agents serving one tunnel is phase 10c.
* **A sidecar is a machine for each pod,** each with its own enrollment, so it suits an app with one
  replica.
* **No controller reads Ingress objects yet** (phase 10d). Tunnels are the declared lines.
