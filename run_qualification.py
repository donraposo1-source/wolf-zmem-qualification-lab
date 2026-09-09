#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

import qualification as q


def main() -> int:
    result = {"runtime": {"python": sys.version, "executable": sys.executable}}
    failed = False
    with tempfile.TemporaryDirectory(prefix="zmem-qualification-") as tmp:
        root = Path(tmp)
        tests = [("T07", q.t07), ("T08", q.t08), ("T09", q.t09), ("T10", q.t10), ("BOUNDARY", q.mcp_boundary)]
        for name, fn in tests:
            started = time.perf_counter()
            try:
                data = fn(root)
                data["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
                result[name] = data
                print(f"{name}=PASS {json.dumps(data, sort_keys=True)}", flush=True)
            except Exception as exc:
                failed = True
                data = {
                    "status": "FAIL",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                }
                result[name] = data
                print(f"{name}=FAIL {json.dumps(data, sort_keys=True)}", flush=True)
    Path("qualification-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("QUALIFICATION_RESULT=" + json.dumps(result, sort_keys=True), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
