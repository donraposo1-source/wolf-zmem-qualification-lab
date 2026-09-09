#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sqlite3
import struct
import sys
from pathlib import Path

from zerker_memory.store import MemoryStore

MAX_REQUEST = 65536


def open_store(path: Path) -> MemoryStore:
    store = MemoryStore(path)
    if hasattr(store, "init"):
        store.init()
    store.conn.execute(
        "CREATE TABLE IF NOT EXISTS boundary_requests ("
        "request_id TEXT PRIMARY KEY, op TEXT NOT NULL, memory_id TEXT, result_json TEXT NOT NULL)"
    )
    store.conn.commit()
    return store


def peer_identity(conn: socket.socket) -> tuple[int, int, int]:
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def response(ok: bool, **fields) -> dict:
    return {"ok": ok, **fields}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--worker-uid", type=int, required=True)
    args = parser.parse_args()

    socket_path = Path(args.socket)
    db_path = Path(args.db)
    curator_uid = os.getuid()
    worker_uid = args.worker_uid
    store = open_store(db_path)

    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, 0o666)
    server.listen(16)

    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True
        try:
            server.close()
        except OSError:
            pass

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(json.dumps({"event": "READY", "curator_uid": curator_uid, "worker_uid": worker_uid}), flush=True)

    while not stopping:
        try:
            conn, _ = server.accept()
        except OSError:
            if stopping:
                break
            raise
        with conn:
            pid, uid, gid = peer_identity(conn)
            payload = b""
            while b"\n" not in payload and len(payload) <= MAX_REQUEST:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                payload += chunk
            if len(payload) > MAX_REQUEST:
                out = response(False, error="REQUEST_TOO_LARGE")
            else:
                try:
                    req = json.loads(payload.split(b"\n", 1)[0].decode("utf-8"))
                    op = req.get("op")
                    if op == "ping":
                        out = response(True, peer_uid=uid)
                    elif op == "propose":
                        if uid != worker_uid:
                            out = response(False, error="PROPOSAL_PEER_FORBIDDEN", peer_uid=uid)
                        else:
                            content = str(req.get("content", ""))[:4096]
                            if not content:
                                out = response(False, error="EMPTY_CONTENT")
                            else:
                                memory = store.remember(
                                    content,
                                    memory_type="semantic",
                                    scope="process-boundary-lab",
                                    source_kind="agent",
                                    actor_id=f"worker-uid:{uid}",
                                    actor_uri=f"unix-peer://uid/{uid}",
                                    source_uri="lab://untrusted-worker/proposal",
                                )
                                out = response(
                                    True,
                                    memory_id=memory.id,
                                    status=memory.status,
                                    source_kind=memory.source_kind,
                                    actor_id=f"worker-uid:{uid}",
                                    claimed_source_ignored=req.get("source"),
                                    claimed_actor_ignored=req.get("actor"),
                                )
                    elif op in {"promote", "revoke", "status"}:
                        if uid != curator_uid:
                            out = response(False, error="PRIVILEGED_PEER_FORBIDDEN", peer_uid=uid)
                        elif op == "status":
                            mid = str(req.get("memory_id", ""))
                            memory = store.get(mid)
                            promoted = store.conn.execute(
                                "SELECT COUNT(*) FROM events WHERE memory_id=? AND event_type='PROMOTED'", (mid,)
                            ).fetchone()[0]
                            out = response(True, memory_id=mid, status=memory.status, promotion_events=promoted)
                        else:
                            request_id = str(req.get("request_id", ""))
                            mid = str(req.get("memory_id", ""))
                            if not request_id or not mid:
                                out = response(False, error="MISSING_REQUEST_ID_OR_MEMORY_ID")
                            else:
                                previous = store.conn.execute(
                                    "SELECT result_json FROM boundary_requests WHERE request_id=?", (request_id,)
                                ).fetchone()
                                if previous:
                                    out = json.loads(previous[0])
                                    out["replayed"] = True
                                elif op == "promote":
                                    allow = req.get("allow")
                                    if allow is not True:
                                        memory = store.get(mid)
                                        out = response(True, decision="DENY", memory_id=mid, status=memory.status)
                                    else:
                                        memory = store.promote(mid, actor_id=f"curator-uid:{uid}")
                                        out = response(True, decision="ALLOW", memory_id=mid, status=memory.status)
                                    store.conn.execute(
                                        "INSERT INTO boundary_requests(request_id,op,memory_id,result_json) VALUES(?,?,?,?)",
                                        (request_id, op, mid, json.dumps(out, sort_keys=True)),
                                    )
                                    store.conn.commit()
                                else:
                                    reason = str(req.get("reason", "generic qualification"))[:256]
                                    memory = store.revoke(mid, actor_id=f"curator-uid:{uid}", reason=reason)
                                    out = response(True, memory_id=mid, status=memory.status)
                                    store.conn.execute(
                                        "INSERT INTO boundary_requests(request_id,op,memory_id,result_json) VALUES(?,?,?,?)",
                                        (request_id, op, mid, json.dumps(out, sort_keys=True)),
                                    )
                                    store.conn.commit()
                    elif op == "shutdown":
                        if uid != curator_uid:
                            out = response(False, error="PRIVILEGED_PEER_FORBIDDEN", peer_uid=uid)
                        else:
                            out = response(True, status="SHUTTING_DOWN")
                            stopping = True
                    else:
                        out = response(False, error="UNKNOWN_OPERATION")
                except Exception as exc:
                    out = response(False, error=type(exc).__name__, message=str(exc))
            conn.sendall((json.dumps(out, sort_keys=True) + "\n").encode("utf-8"))

    try:
        store.conn.close()
    except Exception:
        pass
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
