#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from zerker_memory.mcp import McpServer
from zerker_memory.store import MemoryStore, verify_merkle_proof


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def open_store(path: Path) -> MemoryStore:
    store = MemoryStore(path)
    if hasattr(store, "init"):
        store.init()
    return store


def close_store(store: MemoryStore) -> None:
    try:
        store.conn.close()
    except Exception:
        pass


def records(store: MemoryStore):
    return store.conn.execute(
        "SELECT id, content, status, authority, source_kind FROM memories ORDER BY rowid"
    ).fetchall()


def assert_sqlite_ok(store: MemoryStore) -> None:
    row = store.conn.execute("PRAGMA integrity_check").fetchone()
    value = row[0] if not isinstance(row, dict) else next(iter(row.values()))
    assert value == "ok", f"sqlite integrity_check={value!r}"


def verify_receipt_chain_if_available(store: MemoryStore, memory_id: str) -> bool:
    if not hasattr(store, "memory_write_receipts"):
        return True
    receipts = store.memory_write_receipts(memory_id)
    if not receipts:
        return True
    if hasattr(store, "verify_memory_write_receipt_chain"):
        result = store.verify_memory_write_receipt_chain(receipts)
        return bool(result.get("ok"))
    return all(bool(store.verify_memory_write_receipt(r).get("ok")) for r in receipts)


def worker_t07_loop(db: Path) -> None:
    store = open_store(db)
    payload = "T07 crash-loop candidate " + ("x" * 32768)
    i = 0
    while True:
        store.remember(
            f"{payload} {i}",
            memory_type="semantic",
            scope="lab",
            source_kind="agent",
            actor_id="t07-worker",
            actor_uri="agent://t07/worker",
            session_id="session://t07/crash-loop",
            source_uri=f"lab://t07/{i}",
        )
        i += 1


def worker_t07_promote(db: Path, memory_id: str) -> None:
    store = open_store(db)
    store.promote(memory_id, actor_id="t07-operator")
    print("PROMOTION_RETURNED", flush=True)
    time.sleep(30)


def process_a_t10(db: Path, meta: Path) -> None:
    store = open_store(db)
    canary_id = f"ZMEM-T10-{uuid.uuid4().hex}"
    phrase = f"{canary_id} cobalt orchard {secrets.token_hex(12)}"
    candidate = store.remember(
        phrase,
        memory_type="semantic",
        scope="lab",
        source_kind="agent",
        actor_id="agent-a",
        actor_uri="agent://agent-a/process-a",
        session_id="session://t10/process-a",
        source_uri="lab://t10/process-a/canary",
    )
    assert candidate.status in {"quarantined", "proposed"}
    active = store.promote(candidate.id, actor_id="trusted-operator")
    assert active.status == "active"

    stale = store.remember(
        "ZMEM-T10 stale quarantined decoy",
        memory_type="semantic",
        scope="lab",
        source_kind="agent",
        actor_id="agent-a",
        actor_uri="agent://agent-a/process-a",
        session_id="session://t10/process-a",
        source_uri="lab://t10/process-a/stale",
    )
    assert stale.status in {"quarantined", "proposed"}

    revoked = store.remember(
        "ZMEM-T10 revoked decoy",
        memory_type="semantic",
        scope="lab",
        source_kind="human",
        actor_id="trusted-operator",
        source_uri="lab://t10/process-a/revoked",
    )
    store.revoke(revoked.id, actor_id="trusted-operator", reason="qualification decoy")

    receipt = store.memory_write_receipt(candidate.id)
    meta.write_text(
        json.dumps(
            {
                "canary_id": canary_id,
                "content_sha256": sha256_text(phrase),
                "memory_id": candidate.id,
                "receipt_id": receipt.get("receipt_id"),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    close_store(store)


def process_b_t10(db: Path, out: Path) -> None:
    # This process receives only the persistent store path and a generic
    # instruction encoded in this public harness: retrieve the ZMEM-T10 canary.
    store = open_store(db)
    found = store.search("ZMEM T10", scope="lab")
    assert found, "no active T10 memory recovered"
    canaries = [m for m in found if m.content.startswith("ZMEM-T10-") and "stale" not in m.content and "revoked" not in m.content]
    assert len(canaries) == 1, f"expected one active canary, got {len(canaries)}"
    memory = canaries[0]
    recovered_id = memory.content.split(" ", 1)[0]
    receipt = store.memory_write_receipt(memory.id)
    verification = store.verify_memory_write_receipt(receipt)
    assert verification.get("ok"), verification

    active_search_contents = [m.content for m in found]
    assert not any("stale quarantined decoy" in c for c in active_search_contents)
    assert not any("revoked decoy" in c for c in active_search_contents)

    out.write_text(
        json.dumps(
            {
                "canary_id": recovered_id,
                "content_sha256": sha256_text(memory.content),
                "memory_id": memory.id,
                "status": memory.status,
                "authority": memory.authority,
                "source_kind": memory.source_kind,
                "receipt_id": receipt.get("receipt_id"),
                "receipt_ok": bool(verification.get("ok")),
                "actor_uri": receipt.get("actor_uri"),
                "session_id": receipt.get("session_id"),
                "source_uri": receipt.get("source_uri"),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    close_store(store)


def t07(root: Path) -> dict:
    db = root / "t07.sqlite"
    proc = subprocess.Popen([sys.executable, __file__, "--mode", "t07-loop", "--db", str(db)])
    time.sleep(0.08)
    proc.kill()
    proc.wait(timeout=10)

    store = open_store(db)
    assert_sqlite_ok(store)
    rs = records(store)
    assert rs, "crash loop persisted no completed candidate; boundary not exercised"
    assert all(r["status"] != "active" for r in rs), "phantom active memory after proposal crash"
    for r in rs:
        assert verify_receipt_chain_if_available(store, r["id"]), f"invalid receipt chain for {r['id']}"
    count_before = len(rs)

    candidate = store.remember(
        "T07 promotion durability candidate",
        memory_type="semantic",
        scope="lab",
        source_kind="agent",
        actor_id="t07-agent",
    )
    close_store(store)

    promote_proc = subprocess.Popen(
        [sys.executable, __file__, "--mode", "t07-promote", "--db", str(db), "--memory-id", candidate.id],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    line = promote_proc.stdout.readline().strip()
    assert line == "PROMOTION_RETURNED", line
    promote_proc.kill()
    promote_proc.wait(timeout=10)

    reopened = open_store(db)
    assert_sqlite_ok(reopened)
    promoted = reopened.get(candidate.id)
    assert promoted.status == "active", promoted.status
    event_rows = reopened.conn.execute(
        "SELECT event_type FROM events WHERE memory_id = ? ORDER BY seq", (candidate.id,)
    ).fetchall()
    event_types = [r[0] for r in event_rows]
    assert event_types.count("PROMOTED") == 1, event_types
    assert verify_receipt_chain_if_available(reopened, candidate.id)
    active_count = reopened.conn.execute(
        "SELECT COUNT(*) FROM memories WHERE id = ? AND status = 'active'", (candidate.id,)
    ).fetchone()[0]
    assert active_count == 1
    close_store(reopened)
    return {"status": "PASS", "crash_loop_committed_candidates": count_before, "promotion_event_count": 1}


def t08(root: Path) -> dict:
    db = root / "t08.sqlite"
    store = open_store(db)
    memory = store.remember(
        "T08 native provenance canary",
        memory_type="semantic",
        scope="lab",
        source_kind="agent",
        actor_id="t08-agent",
        actor_uri="agent://t08/a",
        session_id="session://t08/a",
        source_uri="lab://t08/source",
        environment_hash="sha256:generic-lab",
    )
    receipt = store.memory_write_receipt(memory.id)
    valid = store.verify_memory_write_receipt(receipt)
    assert valid.get("ok"), valid

    import copy
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
    action = store.inject("T08 native provenance", agent_id="t08-reader", scope="lab")
    assert store.verify(action["action_id"])
    proof = action["injected_memory_proofs"].get(memory.id)
    assert proof, "missing native Merkle proof"
    assert verify_merkle_proof(proof["leaf_hash"], proof["proof"], proof["root"])
    bad_leaf = ("0" if proof["leaf_hash"][0] != "0" else "1") + proof["leaf_hash"][1:]
    assert not verify_merkle_proof(bad_leaf, proof["proof"], proof["root"])
    bad_root = ("0" if proof["root"][0] != "0" else "1") + proof["root"][1:]
    assert not verify_merkle_proof(proof["leaf_hash"], proof["proof"], bad_root)
    tamper_results["merkle_leaf"] = True
    tamper_results["merkle_root_proof"] = True

    # Persisted event-link tamper must invalidate a receipt/source verification path.
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
    close_store(store)
    return {"status": "PASS", "tamper_rejections": tamper_results}


def t09(root: Path) -> dict:
    source_db = root / "t09-source.sqlite"
    dest_db = root / "t09-dest.sqlite"
    source = open_store(source_db)

    active = source.remember(
        "T09 active memory",
        memory_type="semantic", scope="lab", source_kind="human", actor_id="operator", source_uri="lab://t09/active"
    )
    quarantined = source.remember(
        "T09 quarantined candidate",
        memory_type="semantic", scope="lab", source_kind="agent", actor_id="agent-a", source_uri="lab://t09/quarantine"
    )
    revoked = source.remember(
        "T09 revoked source",
        memory_type="semantic", scope="lab", source_kind="human", actor_id="operator", source_uri="lab://t09/revoked"
    )
    child = source.remember(
        "T09 lineage child",
        memory_type="semantic", scope="lab", source_kind="agent", actor_id="agent-a", parents=[revoked.id], source_uri="lab://t09/child"
    )
    source.revoke(revoked.id, actor_id="operator", reason="qualification")

    snapshot = source.snapshot()
    snapshot_hash = snapshot["snapshot_hash"]
    source_states = {r["id"]: (r["status"], r["authority"], r["source_kind"]) for r in records(source)}
    source_receipts = {mid: source.memory_write_receipts(mid) for mid in source_states}
    close_store(source)

    assert not dest_db.exists()
    dest = open_store(dest_db)
    result = dest.restore_snapshot(snapshot)
    assert result.get("ok"), result
    assert result.get("snapshot_hash") == snapshot_hash
    assert dest.current_merkle_root() == snapshot["merkle_root"]
    dest_states = {r["id"]: (r["status"], r["authority"], r["source_kind"]) for r in records(dest)}
    assert dest_states == source_states, (source_states, dest_states)
    assert dest.get(active.id).status == "active"
    assert dest.get(quarantined.id).status in {"quarantined", "proposed"}
    assert dest.get(revoked.id).status == "revoked"
    assert dest.get(child.id).status == "revoked", dest.get(child.id).status
    for mid, expected in source_receipts.items():
        actual = dest.memory_write_receipts(mid)
        assert [r.get("receipt_id") for r in actual] == [r.get("receipt_id") for r in expected]
        assert verify_receipt_chain_if_available(dest, mid)
    default_contents = [m.content for m in dest.search("T09", scope="lab")]
    assert "T09 active memory" in default_contents
    assert "T09 quarantined candidate" not in default_contents
    assert "T09 revoked source" not in default_contents
    assert "T09 lineage child" not in default_contents
    close_store(dest)
    return {"status": "PASS", "snapshot_hash": snapshot_hash, "memory_count": len(source_states)}


def t10(root: Path) -> dict:
    db = root / "t10.sqlite"
    meta = root / "t10-a-meta.json"
    out = root / "t10-b-output.json"

    a = subprocess.run([sys.executable, __file__, "--mode", "t10-a", "--db", str(db), "--meta", str(meta)], check=False)
    assert a.returncode == 0, f"Process A failed {a.returncode}"
    a_meta = json.loads(meta.read_text(encoding="utf-8"))

    # Fresh Process B gets only persistent DB path and output path; no canary ID/phrase/hash.
    b = subprocess.run([sys.executable, __file__, "--mode", "t10-b", "--db", str(db), "--out", str(out)], check=False)
    assert b.returncode == 0, f"Process B failed {b.returncode}"
    b_out = json.loads(out.read_text(encoding="utf-8"))

    assert b_out["canary_id"] == a_meta["canary_id"]
    assert b_out["content_sha256"] == a_meta["content_sha256"]
    assert b_out["memory_id"] == a_meta["memory_id"]
    assert b_out["receipt_id"] == a_meta["receipt_id"]
    assert b_out["receipt_ok"] is True
    assert b_out["status"] == "active"
    assert b_out["actor_uri"] == "agent://agent-a/process-a"
    assert b_out["session_id"] == "session://t10/process-a"
    assert b_out["source_uri"] == "lab://t10/process-a/canary"

    return {
        "status": "PASS",
        "canary_id": a_meta["canary_id"],
        "canary_phrase_sha256": a_meta["content_sha256"],
        "canary_recovered": True,
        "provenance_recovered": True,
        "process_a_exit": a.returncode,
        "process_b_exit": b.returncode,
    }


def mcp_boundary(root: Path) -> dict:
    db = root / "mcp.sqlite"
    store = open_store(db)
    agent = McpServer(store, profile="agent", agent_id="lab-agent", connection_id="conn-lab")
    operator = McpServer(store, profile="operator")

    def call(server, name, args=None):
        return server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args or {}}})

    agent_tools = {t["name"] for t in agent.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]}
    operator_tools = {t["name"] for t in operator.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]}
    for forbidden in {"memory.remember", "memory.promote", "memory.reject", "memory.revoke", "memory.restore"}:
        assert forbidden not in agent_tools, (forbidden, agent_tools)
    for expected in {"memory.remember", "memory.promote", "memory.reject", "memory.revoke", "memory.restore"}:
        assert expected in operator_tools, (expected, operator_tools)

    proposal_response = call(agent, "memory.propose", {"content": "MCP boundary candidate", "source": "human", "scope": "lab"})
    assert "error" not in proposal_response, proposal_response
    row = store.conn.execute("SELECT id, source_kind, status FROM memories ORDER BY rowid DESC LIMIT 1").fetchone()
    assert row["source_kind"] == "agent"
    assert row["status"] in {"quarantined", "proposed"}
    rejected = call(agent, "memory.promote", {"memory_id": row["id"]})
    assert "error" in rejected and "unavailable in profile=agent" in rejected["error"]["message"]
    direct = store.promote(row["id"], actor_id="direct-python-caller")
    assert direct.status == "active"
    close_store(store)
    return {
        "status": "PASS",
        "agent_profile_self_promotion": "BLOCKED",
        "agent_source_human_spoof": "BLOCKED",
        "operator_governance_surface": "EXPOSED_AS_DESIGNED",
        "direct_library_mutation_boundary": "PRIVILEGED_LIBRARY_CALL_CAN_PROMOTE; EXTERNAL PROCESS/IMPORT ACCESS CONTROL REQUIRED",
    }


def run_all() -> None:
    result = {
        "runtime": {
            "python": sys.version,
            "executable": sys.executable,
        }
    }
    with tempfile.TemporaryDirectory(prefix="zmem-qualification-") as tmp:
        root = Path(tmp)
        tests = [("T07", t07), ("T08", t08), ("T09", t09), ("T10", t10), ("BOUNDARY", mcp_boundary)]
        for name, fn in tests:
            started = time.perf_counter()
            try:
                data = fn(root)
                data["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
                result[name] = data
                print(f"{name}=PASS {json.dumps(data, sort_keys=True)}", flush=True)
            except Exception as exc:
                result[name] = {"status": "FAIL", "error": repr(exc)}
                print(f"{name}=FAIL {exc!r}", flush=True)
                print("QUALIFICATION_RESULT=" + json.dumps(result, sort_keys=True), flush=True)
                raise
    print("QUALIFICATION_RESULT=" + json.dumps(result, sort_keys=True), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="all")
    parser.add_argument("--db")
    parser.add_argument("--memory-id")
    parser.add_argument("--meta")
    parser.add_argument("--out")
    args = parser.parse_args()
    if args.mode == "all":
        run_all()
    elif args.mode == "t07-loop":
        worker_t07_loop(Path(args.db))
    elif args.mode == "t07-promote":
        worker_t07_promote(Path(args.db), args.memory_id)
    elif args.mode == "t10-a":
        process_a_t10(Path(args.db), Path(args.meta))
    elif args.mode == "t10-b":
        process_b_t10(Path(args.db), Path(args.out))
    else:
        raise SystemExit(f"unknown mode: {args.mode}")


if __name__ == "__main__":
    main()
