# MagicPipes in containers and Kubernetes

The agent runs in a container as `magicpipes agent run`, set up entirely by environment variables:
the tunnels it serves are declared there, and it answers a container's health probes. It still
dials out to the server, like any agent, so nothing in the cluster needs to be reachable from
outside it.

There are two ways to use it:

* **A gateway.** One agent in its own Deployment publishes Services by their names in the cluster
  (`80 --host shop.default.svc.cluster.local`), or serves the cluster's [Ingress objects](#ingress)
  of its class. That's one machine for the whole cluster, and with [replicas](#replicas), it can run
  as several pods.
* **A sidecar.** An agent in an app's pod publishes that app at `127.0.0.1`. With replicas, every
  pod of the app is a copy of one machine, and they share its tunnels.

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
| `MAGICPIPES_INGRESS_CLASS` | Serve the cluster's Ingress objects of this class as tunnels ([Ingress](#ingress)) |
| `MAGICPIPES_INGRESS_NAMESPACE` | Only those in this namespace (default: every namespace) |

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
* `/readyz`: 200 once it's connected to the server and every declared tunnel is registered, those
  from Ingress objects included once it has listed them. Without declarations, it's every tunnel the
  agent has. Until then it answers 503, with what it's waiting for:

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
  # Two copies of one machine, which needs replicas on for it (below). Without that, use 1, and
  # `strategy: {type: Recreate}`, since a new copy replaces the old one.
  replicas: 2
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

## Ingress

With `MAGICPIPES_INGRESS_CLASS=magicpipes`, the gateway agent serves the cluster's Ingress objects
of that class as tunnels. There's no separate controller: the agent watches the Kubernetes API with
its pod's service account, and adds, changes and removes tunnels as the objects do. Each Ingress
rule is one tunnel, since a tunnel sends a whole hostname to one backend:

* **The host** is `<name>.<base domain>`, which names the tunnel, or a custom hostname an
  administrator gave this machine. A rule without a host takes its name from the
  `magicpipes.io/name` annotation.
* **One path, `/`** (or none), whose backend is a Service in the Ingress's namespace, by port number
  or name. The agent reaches it at its cluster IP, or a headless one at `<service>.<namespace>.svc`,
  and checks the Service again every minute.
* **Annotations:** `magicpipes.io/visibility` (`public` or `private`; without it, the machine's
  default), `magicpipes.io/tags` (a comma-separated list, which makes it private),
  `magicpipes.io/check-path`, and `magicpipes.io/checks: off`.
* **What can't be served** is logged, once each time the Ingress changes: several paths for one host,
  wildcard hosts, a host with more than one label before the base domain, a missing Service or port.
  It doesn't hold up the agent's readiness, since it never could be served. `spec.tls` is ignored:
  MagicPipes gets the certificates.
* **Status.** Once a rule's tunnel works, the Ingress's `status.loadBalancer.ingress` lists its
  public hostname, which `kubectl get ingress` shows as its address.

Tunnels declared in `MAGICPIPES_TUNNELS` work alongside, and win if both name the same tunnel. Once
the agent has listed the Ingress objects, it removes the tunnels it served that nothing declares.

```yaml
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: magicpipes
spec:
  controller: magicpipes.io/agent
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: magicpipes-gateway
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: magicpipes-gateway
rules:
  - apiGroups: [networking.k8s.io]
    resources: [ingresses]
    verbs: [get, list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses/status]
    verbs: [patch]
  - apiGroups: [""]
    resources: [services]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: magicpipes-gateway
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: magicpipes-gateway}
subjects:
  - {kind: ServiceAccount, name: magicpipes-gateway, namespace: default}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: shop
  annotations:
    magicpipes.io/visibility: public
spec:
  ingressClassName: magicpipes
  rules:
    - host: shop.t.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service: {name: shop, port: {name: http}}
```

In the [gateway](#a-gateway) Deployment, add `serviceAccountName: magicpipes-gateway` to the pod and
`{name: MAGICPIPES_INGRESS_CLASS, value: magicpipes}` to its environment; the ConfigMap of declared
tunnels becomes optional. To watch one namespace, set `MAGICPIPES_INGRESS_NAMESPACE` and use a Role
and RoleBinding there instead.

Anyone who can create an Ingress of the class in a watched namespace can publish that namespace's
Services through this machine, as with any ingress controller: limit who can, with the namespace or
RBAC. Whether a tunnel may be public is still the machine's to decide: one enrolled without public
tunnels refuses a public one, and its rule is logged as not served.

## Replicas

A machine's copies can serve side by side: the pods of a gateway Deployment, or the sidecars of an
app's pods, all with the same identity (one Secret). Turn **Replicas** on for the machine, on its
page in the management UI or with `PATCH /api/v1/agents/{id}` and `{"replicas": true}`; whoever
manages the machine can, and the audit log records it.

* **Off** (the default), a copy that connects replaces the one before, as a laptop's agent does after
  a network change.
* **On**, up to 16 copies stay connected at once, and each gets requests for the tunnels it has
  registered. A copy that's just started takes its share once its own declarations are in. The
  server sends each new request or connection to the least busy connection, so a quiet tunnel may
  stay with one copy until there's more than one request at a time.
* **A copy that goes away**, in a rolling update or a scale-down, stops getting requests once its
  connections close. One that vanishes without closing them, such as on a node that fails, is
  dropped when its pings stop, within `session_timeout_secs` (45 s by default).
* **Turning replicas off** keeps the newest copy, and disconnects the others.

Copies share their tunnels' settings: the last copy to declare a tunnel sets them. During a rolling
update that changes a tunnel's declaration, old and new copies take turns until the old ones are gone.
A tunnel's visibility and tags never change this way: a copy registering a tunnel again after it
reconnects keeps what the server has. The machine page shows how many copies are connected, and from
where. Copies need magicpipes from this version on (protocol 11); an older copy waits for a readiness
probe another copy may answer, and doesn't become ready.

## Docker

```bash
docker run -d --name shop-tunnel --network shop-net -v magicpipes-agent:/data \
  -e MAGICPIPES_SERVER=https://mp.example.com -e MAGICPIPES_TOKEN=mpe_… \
  -e MAGICPIPES_TUNNELS="80 --host shop --name shop --public" \
  magicpipes-agent
```

The token is used once, at the first start. After that the volume holds the identity.

## Limits

* **Different machines can't share a tunnel.** Copies of one machine can (replicas), so give every
  pod that serves a tunnel the same identity.
* **Ingress only**, not the Gateway API (HTTPRoute), and one backend for each host.
