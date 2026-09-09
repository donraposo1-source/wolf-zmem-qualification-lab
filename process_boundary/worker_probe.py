#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import socket
import sqlite3
from pathlib import Path


def call(socket_path: str, request: dict) -> dict:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(socket_path)
    client.sendall((json.dumps(request, sort_keys=True) + "\n").encode("utf-8"))
    data = b""
    while b"\n" not in data:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    client.close()
    return json.loads(data.split(b"\n", 1)[0].decode("utf-8"))


def denied_read(path: Path) -> bool:
    try:
        path.read_bytes()
        return False
    except (PermissionError, FileNotFoundError, IsADirectoryError):
        return True


def denied_write(path: Path) -> bool:
    try:
        with path.open("ab") as handle:
            handle.write(b"worker-tamper")
        return False
    except (PermissionError, FileNotFoundError, IsADirectoryError):
        return True


def denied_db_write(db: Path) -> bool:
    try:
        conn = sqlite3.connect(f"file:{db}?mode=rw", uri=True)
        conn.execute("CREATE TABLE worker_attack(x TEXT)")
        conn.commit()
        conn.close()
        return False
    except (sqlite3.Error, PermissionError):
        return True


def inherited_fd_paths() -> list[str]:
    values = []
    for item in Path("/proc/self/fd").iterdir():
        try:
            values.append(os.readlink(item))
        except OSError:
            continue
    return values


def initial(args) -> dict:
    trusted_root = Path(args.trusted_root)
    trusted_module = trusted_root / "app" / "curator_server.py"
    db = Path(args.db)

    sensitive_env_names = [k for k in os.environ if any(word in k.upper() for word in ("TOKEN", "SECRET", "CAPABILITY", "CURATOR"))]
    cmdline = Path("/proc/self/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
    cmdline_has_secret_marker = any(marker in cmdline.upper() for marker in ("TOKEN=", "SECRET=", "CAPABILITY="))
    cwd = os.getcwd()
    fd_paths = inherited_fd_paths()
    socket_stat = os.stat(args.socket)

    p01_import_unavailable = importlib.util.find_spec("zerker_memory") is None
    p01_module_unreadable = denied_read(trusted_module)
    p02_db_denied = denied_db_write(db)

    spoof = call(args.socket, {
        "op": "propose",
        "content": "P04 spoof attempt",
        "source": "human",
        "actor": "operator",
    })
    p04 = bool(spoof.get("ok")) and spoof.get("source_kind") == "agent" and str(spoof.get("actor_id", "")).startswith("worker-uid:")

    direct_promote = call(args.socket, {
        "op": "promote",
        "memory_id": spoof.get("memory_id", "missing"),
        "allow": True,
        "request_id": "worker-direct-p05",
    })
    p05 = (not direct_promote.get("ok")) and direct_promote.get("error") == "PRIVILEGED_PEER_FORBIDDEN"

    ordinary = call(args.socket, {
        "op": "propose",
        "content": "P06 ordinary candidate",
        "source": "agent",
        "actor": "worker",
    })
    p06 = bool(ordinary.get("ok")) and ordinary.get("status") in {"quarantined", "proposed"}

    deny_candidate = call(args.socket, {"op": "propose", "content": "P08 denied candidate"})
    restart_candidate = call(args.socket, {"op": "propose", "content": "P12 restart candidate"})

    attacker_dir = Path(args.worker_dir) / "attacker_path"
    attacker_dir.mkdir(parents=True, exist_ok=True)
    (attacker_dir / "zerker_memory.py").write_text("ATTACKER_CONTROLLED=True\n", encoding="utf-8")
    os.environ["PYTHONPATH"] = str(attacker_dir)
    p10_write_denied = denied_write(trusted_module)
    try:
        os.chdir(trusted_root / "app")
        p10_chdir_denied = False
    except PermissionError:
        p10_chdir_denied = True

    p03 = (
        not sensitive_env_names
        and int(args.operator_uid) != os.geteuid()
        and not cmdline_has_secret_marker
        and all(args.trusted_root not in value and args.db not in value for value in fd_paths)
        and denied_read(trusted_root)
    )

    return {
        "P01": p01_import_unavailable and p01_module_unreadable,
        "P01_import_unavailable": p01_import_unavailable,
        "P01_trusted_module_unreadable": p01_module_unreadable,
        "P02": p02_db_denied,
        "P03": p03,
        "P03_sensitive_env_names": sensitive_env_names,
        "P03_cmdline_has_secret_marker": cmdline_has_secret_marker,
        "P03_cwd": cwd,
        "P03_fd_paths": fd_paths,
        "P03_socket_mode": oct(socket_stat.st_mode & 0o777),
        "P03_socket_uid": socket_stat.st_uid,
        "P04": p04,
        "P05": p05,
        "P06": p06,
        "P10": p10_write_denied and p10_chdir_denied,
        "P10_trusted_module_write_denied": p10_write_denied,
        "P10_trusted_cwd_denied": p10_chdir_denied,
        "P11": p02_db_denied,
        "spoof_candidate": spoof.get("memory_id"),
        "promotion_candidate": ordinary.get("memory_id"),
        "deny_candidate": deny_candidate.get("memory_id"),
        "restart_candidate": restart_candidate.get("memory_id"),
        "worker_euid": os.geteuid(),
        "operator_uid": int(args.operator_uid),
    }


def replay(args) -> dict:
    request = json.loads(Path(args.replay_file).read_text(encoding="utf-8"))
    result = call(args.socket, request)
    return {
        "P09_worker_replay_denied": (not result.get("ok")) and result.get("error") == "PRIVILEGED_PEER_FORBIDDEN",
        "result": result,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["initial", "replay"])
    parser.add_argument("--socket", required=True)
    parser.add_argument("--trusted-root", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--worker-dir", required=True)
    parser.add_argument("--operator-uid", required=True)
    parser.add_argument("--replay-file")
    args = parser.parse_args()
    result = initial(args) if args.mode == "initial" else replay(args)
    print(json.dumps(result, sort_keys=True))
    canonical_tests = {f"P{i:02d}" for i in range(1, 13)}
    relevant = [value for key, value in result.items() if key in canonical_tests]
    return 0 if relevant and all(value is True for value in relevant) else 1


if __name__ == "__main__":
    raise SystemExit(main())
