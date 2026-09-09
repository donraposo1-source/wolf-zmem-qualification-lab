#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--json", required=True)
    args = parser.parse_args()
    result = call(args.socket, json.loads(args.json))
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
