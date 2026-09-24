#!/usr/bin/env python3
"""PUBLIC_SAFE synthetic CPU worker. No network, secrets, or Wolf private inputs."""
import hashlib, json, time

ITERATIONS = 350_000
seed = b"WOLF_PUBLIC_SAFE_CLOUD_HEAVY_V1"
start = time.monotonic()
state = seed
for i in range(ITERATIONS):
    state = hashlib.sha256(state + i.to_bytes(4, "big")).digest()
duration_ms = int((time.monotonic() - start) * 1000)
result = {
    "schema": "wolf-cloud-worker-v1",
    "class": "PUBLIC_SAFE",
    "workload": "synthetic-sha256-chain",
    "iterations": ITERATIONS,
    "input_sha256": hashlib.sha256(seed).hexdigest(),
    "output_sha256": hashlib.sha256(state).hexdigest(),
    "duration_ms": duration_ms,
    "exit_code": 0,
    "eur_spend": "0",
    "final_status": "DONE",
}
print(json.dumps(result, sort_keys=True))
