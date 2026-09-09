#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import qualification as q


def t07(root: Path) -> dict:
    db = root / "t07.sqlite"
    proc = subprocess.Popen([sys.executable, q.__file__, "--mode", "t07-loop", "--db", str(db)])
    deadline = time.monotonic() + 5
    committed = 0
    while time.monotonic() < deadline:
        if db.exists():
            try:
                conn = sqlite3.connect(db, timeout=0.05)
                committed = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
                conn.close()
                if committed >= 1:
                    break
            except sqlite3.Error:
                pass
        time.sleep(0.01)
    assert committed >= 1, "crash worker never reached a committed candidate"
    time.sleep(0.005)
    proc.kill()
    proc.wait(timeout=10)

    store = q.open_store(db)
    q.assert_sqlite_ok(store)
    rs = q.records(store)
    assert rs, "no completed candidate survived crash"
    assert all(r["status"] != "active" for r in rs), "phantom active memory after proposal crash"
    for r in rs:
        assert q.verify_receipt_chain_if_available(store, r["id"]), f"invalid receipt chain for {r['id']}"
    count_before = len(rs)
    candidate = store.remember(
        "T07 promotion durability candidate", memory_type="semantic", scope="lab",
        source_kind="agent", actor_id="t07-agent"
    )
    q.close_store(store)

    promote_proc = subprocess.Popen(
        [sys.executable, q.__file__, "--mode", "t07-promote", "--db", str(db), "--memory-id", candidate.id],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    line = promote_proc.stdout.readline().strip()
    assert line == "PROMOTION_RETURNED", line
    promote_proc.kill()
    promote_proc.wait(timeout=10)

    reopened = q.open_store(db)
    q.assert_sqlite_ok(reopened)
    promoted = reopened.get(candidate.id)
    assert promoted.status == "active", promoted.status
    event_rows = reopened.conn.execute(
        "SELECT event_type FROM events WHERE memory_id = ? ORDER BY seq", (candidate.id,)
    ).fetchall()
    event_types = [r[0] for r in event_rows]
    assert event_types.count("PROMOTED") == 1, event_types
    assert q.verify_receipt_chain_if_available(reopened, candidate.id)
    active_count = reopened.conn.execute(
        "SELECT COUNT(*) FROM memories WHERE id = ? AND status = 'active'", (candidate.id,)
    ).fetchone()[0]
    assert active_count == 1
    q.close_store(reopened)
    return {"status": "PASS", "crash_loop_committed_candidates": count_before, "promotion_event_count": 1}


def t08(root: Path) -> dict:
    db = root / "t08.sqlite"
    store = q.open_store(db)
    memory = store.remember(
        "T08 native provenance canary", memory_type="semantic", scope="lab", source_kind="agent",
        actor_id="t08-agent", actor_uri="agent://t08/a", session_id="session://t08/a",
        source_uri="lab://t08/source", environment_hash="sha256:generic-lab",
    )
    receipt = store.memory_write_receipt(memory.id)
    valid = store.verify_memory_write_receipt(receipt)
    assert valid.get("ok"), valid

    tamper_results = {}
    mutations = {
        "content_digest": lambda r: r.__setitem__("content_digest", "sha256:" + "0" * 64),
        "actor_uri": lambda r: r.__setitem__("actor_uri", "agent://tampered"),
        "receipt_hash": lambda r: r.__setitem__("receipt_hash", "0" * 64),
        "merkle_root": lambda r: r.__setitem__("merkle_root", "0" * 64),
    }
    for name, mutate in mutations.items():
        candidate = copy.deepcopy(receipt)
        mutate(candidate)
        result = store.verify_memory_write_receipt(candidate)
        tamper_results[name] = not bool(result.get("ok"))
        assert tamper_results[name], f"native receipt accepted tampered {name}: {result}"

    active = store.promote(memory.id, actor_id="t08-operator")
    assert active.status == "active"
    action = store.inject("T08 native provenance", agent_id="t08-reader", risk="medium", scope="lab")
    assert store.verify(action["action_id"])
    proof = action["injected_memory_proofs"].get(memory.id)
    assert proof, "missing native Merkle proof"
    assert q.verify_merkle_proof(proof["leaf_hash"], proof["proof"], proof["root"])
    bad_leaf = ("0" if proof["leaf_hash"][0] != "0" else "1") + proof["leaf_hash"][1:]
    assert not q.verify_merkle_proof(bad_leaf, proof["proof"], proof["root"])
    bad_root = ("0" if proof["root"][0] != "0" else "1") + proof["root"][1:]
    assert not q.verify_merkle_proof(proof["leaf_hash"], proof["proof"], bad_root)
    tamper_results["merkle_leaf"] = True
    tamper_results["merkle_root_proof"] = True

    event = store.conn.execute(
        "SELECT seq, prev_event_hash FROM events WHERE memory_id = ? ORDER BY seq LIMIT 1", (memory.id,)
    ).fetchone()
    original_prev = event["prev_event_hash"]
    store.conn.execute("UPDATE events SET prev_event_hash = ? WHERE seq = ?", ("f" * 64, event["seq"]))
    store.conn.commit()
    post = store.verify_memory_write_receipt(receipt)
    tamper_results["event_linkage"] = not bool(post.get("ok"))
    assert tamper_results["event_linkage"], f"native verification accepted tampered event linkage: {post}"
    store.conn.execute("UPDATE events SET prev_event_hash = ? WHERE seq = ?", (original_prev, event["seq"]))
    store.conn.commit()
    assert store.verify_memory_write_receipt(receipt).get("ok")
    q.close_store(store)
    return {"status": "PASS", "tamper_rejections": tamper_results}


def main() -> int:
    result = {"runtime": {"python": sys.version, "executable": sys.executable}}
    failed = False
    with tempfile.TemporaryDirectory(prefix="zmem-qualification-") as tmp:
        root = Path(tmp)
        tests = [("T07", t07), ("T08", t08), ("T09", q.t09), ("T10", q.t10), ("BOUNDARY", q.mcp_boundary)]
        for name, fn in tests:
            started = time.perf_counter()
            try:
                data = fn(root)
                data["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
                result[name] = data
                print(f"{name}=PASS {json.dumps(data, sort_keys=True)}", flush=True)
            except Exception as exc:
                failed = True
                data = {"status": "FAIL", "error_type": type(exc).__name__, "error": str(exc),
                        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3)}
                result[name] = data
                print(f"{name}=FAIL {json.dumps(data, sort_keys=True)}", flush=True)
    Path("qualification-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("QUALIFICATION_RESULT=" + json.dumps(result, sort_keys=True), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
