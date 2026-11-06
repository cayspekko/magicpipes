#!/usr/bin/env python3
"""Keeps the control plane busy for `bench.sh control`.

  control.py seed <database>                   1000 tunnels and 150 users, with the server stopped
  control.py tags <token> <port> <clients> <seconds>     changes a tag in a loop, which publishes
  control.py enroll <token> <port> <clients> <seconds>   creates enrollment tokens, which only writes
"""

import hashlib
import http.client
import json
import ssl
import sqlite3
import sys
import threading
import time

AGENTS, TUNNELS_PER_AGENT, USERS = 10, 100, 150
ORG = "org_default"
TAG = "bench"


def seed(database):
    """Written directly, because agents are the only ones who can register tunnels. Follows the
    schema in `magicpipes-server/src/store`: if that changes, this fails loudly."""
    db = sqlite3.connect(database)
    now = int(time.time())
    db.execute("INSERT INTO tags(org_id, name, access, created_at) VALUES(?, ?, 1, ?)", (ORG, TAG, now))
    for i in range(USERS):
        user, tag = f"us_bench{i}", f"personal-{i}"
        db.execute("INSERT INTO users(id, email, created_at) VALUES(?, ?, ?)", (user, f"u{i}@example.com", now))
        db.execute("INSERT INTO memberships(org_id, user_id, role, created_at) VALUES(?, ?, 'member', ?)", (ORG, user, now))
        db.execute("INSERT INTO tags(org_id, name, access, user_id, created_at) VALUES(?, ?, 1, ?, ?)", (ORG, tag, user, now))
        db.execute("INSERT INTO user_tags(org_id, user_id, tag, created_at) VALUES(?, ?, ?, ?)", (ORG, user, tag, now))
    for a in range(AGENTS):
        agent = f"ag_bench{a}"
        token_hash = hashlib.sha256(agent.encode()).hexdigest()
        db.execute(
            "INSERT INTO agents(id, name, token_hash, created_at, owner_user_id) VALUES(?, ?, ?, ?, ?)",
            (agent, f"bench-{a}", token_hash, now, f"us_bench{a % USERS}"),
        )
        for t in range(TUNNELS_PER_AGENT):
            tunnel, name = f"tn_bench{a}x{t}", f"bench{a}x{t}"
            db.execute(
                "INSERT INTO tunnels(id, name, hostname, agent_id, target, created_at, kind, allow, visibility)"
                " VALUES(?, ?, ?, ?, 'http://127.0.0.1:9', ?, 'http', '', ?)",
                (tunnel, name, f"{name}.t.test", agent, now, "private" if t % 2 else "public"),
            )
            db.execute(
                "INSERT INTO tunnel_tags(tunnel_id, org_id, tag) VALUES(?, ?, ?)",
                (tunnel, ORG, f"personal-{a % USERS}"),
            )
    db.commit()


def hammer(name, method, path, body, token, port, clients, seconds):
    """Sends requests from `clients` connections and prints a line in bench.sh's format."""
    # The server's development certificate, on this machine, with a throwaway token.
    context = ssl._create_unverified_context()
    headers = {"authorization": f"Bearer {token}", "content-type": "application/json"}
    latencies, statuses, lock = [], {}, threading.Lock()
    deadline = time.time() + seconds

    def client():
        conn = http.client.HTTPSConnection("localhost", port, context=context)
        access = True
        while time.time() < deadline:
            access = not access
            began = time.perf_counter()
            conn.request(method, path, json.dumps(body(access)), headers)
            response = conn.getresponse()
            response.read()
            with lock:
                latencies.append((time.perf_counter() - began) * 1000)
                statuses[response.status] = statuses.get(response.status, 0) + 1

    threads = [threading.Thread(target=client) for _ in range(clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    latencies.sort()
    at = lambda p: latencies[min(len(latencies) - 1, int(len(latencies) * p))]
    status = ",".join(f"{code}:{n}" for code, n in sorted(statuses.items()))
    print(f"test={name} key=rps rps={len(latencies) / seconds:.0f} p50={at(0.5):.2f} p99={at(0.99):.2f} status={status}")


def main():
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "seed":
        seed(args[1])
    elif len(args) == 5 and args[0] == "tags":
        hammer("tag_changes", "PATCH", f"/api/v1/tags/{TAG}", lambda access: {"access": access}, args[1], int(args[2]), int(args[3]), float(args[4]))
    elif len(args) == 5 and args[0] == "enroll":
        hammer("database_writes", "POST", "/api/v1/enrollments", lambda _: {}, args[1], int(args[2]), int(args[3]), float(args[4]))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
