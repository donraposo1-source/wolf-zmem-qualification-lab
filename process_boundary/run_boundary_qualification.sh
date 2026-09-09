#!/usr/bin/env bash
set -euo pipefail

: "${ZMEM_WHEEL:?ZMEM_WHEEL is required}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"

RESULT_DIR="$GITHUB_WORKSPACE/boundary-evidence"
TRUSTED_ROOT=/opt/zmem-curator
TRUSTED_APP="$TRUSTED_ROOT/app"
TRUSTED_VENV="$TRUSTED_ROOT/venv"
DB_DIR=/var/lib/zmem-curator
DB="$DB_DIR/trusted.sqlite"
SOCKET_DIR=/run/zmem-boundary
SOCKET="$SOCKET_DIR/curator.sock"
WORKER_DIR=/tmp/zmem-worker
CURATOR_USER=zmemcurator
WORKER_USER=zmemworker

mkdir -p "$RESULT_DIR"
chmod 0700 "$RESULT_DIR"

cleanup() {
  sudo pkill -KILL -u "$CURATOR_USER" -f "$TRUSTED_APP/curator_server.py" >/dev/null 2>&1 || true
  chmod 0755 "$GITHUB_WORKSPACE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sudo userdel -r "$CURATOR_USER" >/dev/null 2>&1 || true
sudo userdel -r "$WORKER_USER" >/dev/null 2>&1 || true
sudo useradd --system --create-home --home-dir "/home/$CURATOR_USER" --shell /usr/sbin/nologin "$CURATOR_USER"
sudo useradd --system --create-home --home-dir "/home/$WORKER_USER" --shell /usr/sbin/nologin "$WORKER_USER"
CURATOR_UID="$(id -u "$CURATOR_USER")"
WORKER_UID="$(id -u "$WORKER_USER")"

sudo install -d -m 0750 -o "$CURATOR_USER" -g "$CURATOR_USER" "$TRUSTED_ROOT" "$TRUSTED_APP"
sudo install -d -m 0700 -o "$CURATOR_USER" -g "$CURATOR_USER" "$DB_DIR"
sudo install -d -m 0777 -o root -g root "$SOCKET_DIR"
sudo install -d -m 0700 -o "$WORKER_USER" -g "$WORKER_USER" "$WORKER_DIR"

sudo -u "$CURATOR_USER" python -m venv "$TRUSTED_VENV"
sudo -u "$CURATOR_USER" "$TRUSTED_VENV/bin/python" -m pip install --disable-pip-version-check "$ZMEM_WHEEL" >"$RESULT_DIR/zmem-install.log" 2>&1

sudo install -m 0640 -o "$CURATOR_USER" -g "$CURATOR_USER" "$GITHUB_WORKSPACE/process_boundary/curator_server.py" "$TRUSTED_APP/curator_server.py"
sudo install -m 0640 -o "$CURATOR_USER" -g "$CURATOR_USER" "$GITHUB_WORKSPACE/process_boundary/ipc_client.py" "$TRUSTED_APP/ipc_client.py"
sudo install -m 0640 -o "$WORKER_USER" -g "$WORKER_USER" "$GITHUB_WORKSPACE/process_boundary/worker_probe.py" "$WORKER_DIR/worker_probe.py"

TRUSTED_HASH_BEFORE="$(sudo sha256sum "$TRUSTED_APP/curator_server.py" | awk '{print $1}')"

# The untrusted process cannot traverse the checked-out repository after staging its probe.
chmod 0700 "$GITHUB_WORKSPACE"

start_curator() {
  sudo rm -f "$SOCKET"
  sudo -u "$CURATOR_USER" env -i \
    HOME="/home/$CURATOR_USER" \
    PATH="$TRUSTED_VENV/bin:/usr/bin:/bin" \
    "$TRUSTED_VENV/bin/python" "$TRUSTED_APP/curator_server.py" \
      --socket "$SOCKET" --db "$DB" --worker-uid "$WORKER_UID" \
      >>"$RESULT_DIR/curator.log" 2>&1 &
  CURATOR_LAUNCH_PID=$!
  for _ in $(seq 1 100); do
    [[ -S "$SOCKET" ]] && return 0
    sleep 0.05
  done
  echo "curator socket did not become ready" >&2
  return 1
}

admin_call() {
  local payload="$1"
  sudo -u "$CURATOR_USER" env -i \
    HOME="/home/$CURATOR_USER" PATH="$TRUSTED_VENV/bin:/usr/bin:/bin" \
    "$TRUSTED_VENV/bin/python" "$TRUSTED_APP/ipc_client.py" \
      --socket "$SOCKET" --json "$payload"
}

json_field() {
  local file="$1"
  local field="$2"
  python3 - "$file" "$field" <<'PY'
import json, sys
obj=json.load(open(sys.argv[1], encoding='utf-8'))
value=obj[sys.argv[2]]
print(str(value).lower() if isinstance(value,bool) else value)
PY
}

start_curator

sudo -u "$WORKER_USER" env -i \
  HOME="/home/$WORKER_USER" PATH=/usr/bin:/bin \
  /usr/bin/python3 "$WORKER_DIR/worker_probe.py" initial \
    --socket "$SOCKET" \
    --trusted-root "$TRUSTED_ROOT" \
    --db "$DB" \
    --worker-dir "$WORKER_DIR" \
    --operator-uid "$CURATOR_UID" \
  >"$RESULT_DIR/worker-initial.json"

PROMOTION_ID="$(json_field "$RESULT_DIR/worker-initial.json" promotion_candidate)"
DENY_ID="$(json_field "$RESULT_DIR/worker-initial.json" deny_candidate)"
RESTART_ID="$(json_field "$RESULT_DIR/worker-initial.json" restart_candidate)"

PROMOTE_JSON="$(python3 - "$PROMOTION_ID" <<'PY'
import json,sys
print(json.dumps({'op':'promote','memory_id':sys.argv[1],'allow':True,'request_id':'p07-once'}, sort_keys=True))
PY
)"
DENY_JSON="$(python3 - "$DENY_ID" <<'PY'
import json,sys
print(json.dumps({'op':'promote','memory_id':sys.argv[1],'allow':False,'request_id':'p08-deny'}, sort_keys=True))
PY
)"

admin_call "$PROMOTE_JSON" >"$RESULT_DIR/p07-promote.json"
admin_call "$(python3 - "$PROMOTION_ID" <<'PY'
import json,sys
print(json.dumps({'op':'status','memory_id':sys.argv[1]}))
PY
)" >"$RESULT_DIR/p07-status-before-replay.json"

admin_call "$DENY_JSON" >"$RESULT_DIR/p08-deny.json"
admin_call "$(python3 - "$DENY_ID" <<'PY'
import json,sys
print(json.dumps({'op':'status','memory_id':sys.argv[1]}))
PY
)" >"$RESULT_DIR/p08-status.json"

# Exact once semantics for a trusted request ID.
admin_call "$PROMOTE_JSON" >"$RESULT_DIR/p09-admin-replay.json"

printf '%s\n' "$PROMOTE_JSON" | sudo tee "$WORKER_DIR/replay.json" >/dev/null
sudo chown "$WORKER_USER:$WORKER_USER" "$WORKER_DIR/replay.json"
sudo chmod 0600 "$WORKER_DIR/replay.json"
sudo -u "$WORKER_USER" env -i \
  HOME="/home/$WORKER_USER" PATH=/usr/bin:/bin \
  /usr/bin/python3 "$WORKER_DIR/worker_probe.py" replay \
    --socket "$SOCKET" \
    --trusted-root "$TRUSTED_ROOT" \
    --db "$DB" \
    --worker-dir "$WORKER_DIR" \
    --operator-uid "$CURATOR_UID" \
    --replay-file "$WORKER_DIR/replay.json" \
  >"$RESULT_DIR/p09-worker-replay.json"

admin_call "$(python3 - "$PROMOTION_ID" <<'PY'
import json,sys
print(json.dumps({'op':'status','memory_id':sys.argv[1]}))
PY
)" >"$RESULT_DIR/p09-status-after-replay.json"

admin_call "$(python3 - "$RESTART_ID" <<'PY'
import json,sys
print(json.dumps({'op':'status','memory_id':sys.argv[1]}))
PY
)" >"$RESULT_DIR/p12-before-kill.json"

# Hard death: SIGKILL prevents graceful cleanup and exercises durable state only.
sudo pkill -KILL -u "$CURATOR_USER" -f "$TRUSTED_APP/curator_server.py" || true
wait "$CURATOR_LAUNCH_PID" 2>/dev/null || true
sleep 0.1
start_curator

admin_call "$(python3 - "$RESTART_ID" <<'PY'
import json,sys
print(json.dumps({'op':'status','memory_id':sys.argv[1]}))
PY
)" >"$RESULT_DIR/p12-after-restart.json"
admin_call "$(python3 - "$PROMOTION_ID" <<'PY'
import json,sys
print(json.dumps({'op':'status','memory_id':sys.argv[1]}))
PY
)" >"$RESULT_DIR/p07-after-restart.json"

TRUSTED_HASH_AFTER="$(sudo sha256sum "$TRUSTED_APP/curator_server.py" | awk '{print $1}')"

sudo stat -c 'PATH=%n MODE=%a OWNER=%U GROUP=%G' \
  "$TRUSTED_ROOT" "$TRUSTED_APP" "$TRUSTED_APP/curator_server.py" "$DB_DIR" "$DB" "$SOCKET" \
  >"$RESULT_DIR/os-permissions.log"

python3 - "$RESULT_DIR" "$CURATOR_UID" "$WORKER_UID" "$TRUSTED_HASH_BEFORE" "$TRUSTED_HASH_AFTER" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
curator_uid=int(sys.argv[2]); worker_uid=int(sys.argv[3])
hash_before=sys.argv[4]; hash_after=sys.argv[5]
def load(name): return json.loads((root/name).read_text(encoding='utf-8'))
initial=load('worker-initial.json')
p07=load('p07-promote.json')
p07s=load('p07-status-before-replay.json')
p08=load('p08-deny.json')
p08s=load('p08-status.json')
p09a=load('p09-admin-replay.json')
p09w=load('p09-worker-replay.json')
p09s=load('p09-status-after-replay.json')
p12b=load('p12-before-kill.json')
p12a=load('p12-after-restart.json')
p07r=load('p07-after-restart.json')

results={
  'P01': bool(initial['P01']),
  'P02': bool(initial['P02']),
  'P03': bool(initial['P03']),
  'P04': bool(initial['P04']),
  'P05': bool(initial['P05']),
  'P06': bool(initial['P06']),
  'P07': bool(p07.get('ok') and p07.get('decision')=='ALLOW' and p07.get('status')=='active' and p07s.get('promotion_events')==1),
  'P08': bool(p08.get('ok') and p08.get('decision')=='DENY' and p08s.get('status') in ('quarantined','proposed') and p08s.get('promotion_events')==0),
  'P09': bool(p09a.get('ok') and p09a.get('replayed') is True and p09w.get('P09_worker_replay_denied') is True and p09s.get('promotion_events')==1),
  'P10': bool(initial['P10'] and hash_before==hash_after),
  'P11': bool(initial['P11']),
  'P12': bool(p12b.get('status') in ('quarantined','proposed') and p12b.get('promotion_events')==0 and p12a.get('status')==p12b.get('status') and p12a.get('promotion_events')==0 and p07r.get('promotion_events')==1),
}
summary={
  **results,
  'WORKER_CAN_IMPORT_PRIVILEGED_SURFACE': not results['P01'],
  'WORKER_CAN_WRITE_TRUSTED_DB': not results['P11'],
  'WORKER_HAS_OPERATOR_CAPABILITY': not results['P03'],
  'WORKER_CAN_SELF_PROMOTE': not results['P05'],
  'CURATOR_CAN_PROMOTE': results['P07'],
  'CURATOR_RESTART_SAFE': results['P12'],
  'OS_ENFORCEMENT_USED': 'separate Unix UIDs + directory/file mode enforcement + AF_UNIX SO_PEERCRED peer UID authorization',
  'LIMITATIONS': 'Single GitHub-hosted Linux VM and kernel; this qualifies same-host Unix process/filesystem isolation, not containers, separate machines, production tenant isolation, or Wolf policy correctness.',
  'EUR_SPEND': '0.00',
  'curator_uid': curator_uid,
  'worker_uid': worker_uid,
  'trusted_module_sha256_before': hash_before,
  'trusted_module_sha256_after': hash_after,
}
failed=[name for name,value in results.items() if not value]
summary['P0']=[] if not failed else ['boundary test failure: '+','.join(failed)]
summary['P1']=[]
summary['P2']=['same-kernel/same-runner qualification only; production deployment and tenant isolation remain unqualified']
summary['FINAL_BOUNDARY_VERDICT']='PROCESS_BOUNDARY_QUALIFIED' if not failed else 'REJECTED'
(root/'boundary-result.json').write_text(json.dumps(summary, indent=2, sort_keys=True)+'\n', encoding='utf-8')
print('BOUNDARY_RESULT='+json.dumps(summary, sort_keys=True))
if failed:
    raise SystemExit('FAILED='+','.join(failed))
PY

cat "$RESULT_DIR/boundary-result.json"
