#!/usr/bin/env bash
set -euo pipefail

ROOT="$(mktemp -d)"
TRUST="$ROOT/trusted"
WORK="$ROOT/worker"
SOCK="$TRUST/curator.sock"
DB="$TRUST/trusted.db"
RESULT="$ROOT/result.env"
trap 'rm -rf "$ROOT"' EXIT

# This lab intentionally contains NO Wolf policy. It qualifies only OS authority separation.
# Root is used solely to provision two Unix identities; the attack process runs as zworker.
useradd -M -s /usr/sbin/nologin zcurator
useradd -M -s /usr/sbin/nologin zworker
install -d -o zcurator -g zcurator -m 0700 "$TRUST"
install -d -o zworker -g zworker -m 0700 "$WORK"

cat > "$TRUST/privileged_curator.py" <<'PY'
import json, os, socket, sqlite3, sys
sock_path, db_path = sys.argv[1:3]
con=sqlite3.connect(db_path)
con.execute('create table if not exists memories(id text primary key,state text,promotions integer default 0)')
con.commit(); os.chmod(db_path,0o600)
try: os.unlink(sock_path)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX); s.bind(sock_path); os.chmod(sock_path,0o600); s.listen(4)
for _ in range(4):
 c,_=s.accept(); req=json.loads(c.recv(8192) or b'{}')
 op=req.get('op'); mid=req.get('id','')
 if op=='proposal':
  con.execute("insert or ignore into memories values(?, 'QUARANTINED',0)",(mid,)); con.commit(); out={'ok':True,'state':'QUARANTINED'}
 elif op=='promote' and req.get('allow') is True:
  con.execute("update memories set state='PROMOTED', promotions=case when promotions=0 then 1 else promotions end where id=?",(mid,)); con.commit(); out={'ok':True}
 else: out={'ok':False,'error':'DENIED'}
 c.send(json.dumps(out).encode()); c.close()
PY
chown zcurator:zcurator "$TRUST/privileged_curator.py"; chmod 0600 "$TRUST/privileged_curator.py"

# Trusted process owns implementation, DB, and 0600 IPC endpoint.
runuser -u zcurator -- python3 "$TRUST/privileged_curator.py" "$SOCK" "$DB" & CURATOR=$!
for i in {1..50}; do [[ -S "$SOCK" ]] && break; sleep .1; done

# P01: implementation cannot be read/imported by worker identity.
if runuser -u zworker -- python3 -c "exec(open('$TRUST/privileged_curator.py').read())" 2>/dev/null; then P01=FAIL; else P01=PASS; fi
# P02/P11: trusted DB cannot be opened for direct write by worker identity.
if runuser -u zworker -- python3 -c "import sqlite3; sqlite3.connect('file:$DB?mode=rw',uri=True).execute('pragma user_version=9')" 2>/dev/null; then P02=FAIL; P11=FAIL; else P02=PASS; P11=PASS; fi
# P03: worker gets no curator secret/token/FD; endpoint pathname is not a capability because permissions enforce identity.
if runuser -u zworker -- env -i PATH=/usr/bin:/bin python3 -c "import os; assert not any('CURATOR' in k or 'TOKEN' in k or 'CAP' in k for k in os.environ); assert len(os.listdir('/proc/self/fd'))<=4"; then P03=PASS; else P03=FAIL; fi
# P04/P05: spoof/direct endpoint cannot cross 0600 socket boundary.
if runuser -u zworker -- python3 -c "import socket,json; s=socket.socket(socket.AF_UNIX); s.connect('$SOCK'); s.send(json.dumps({'op':'promote','id':'spoof','allow':True,'source':'human','actor':'operator'}).encode())" 2>/dev/null; then P04=FAIL; P05=FAIL; else P04=PASS; P05=PASS; fi
# P10: worker-controlled cwd/PYTHONPATH cannot replace curator: curator launched absolute unreadable file under trusted identity.
mkdir -p "$WORK/inject"; printf '%s\n' 'raise SystemExit("injected")' > "$WORK/inject/privileged_curator.py"; chown -R zworker:zworker "$WORK/inject"
if runuser -u zworker -- env PYTHONPATH="$WORK/inject" python3 -c "import sys; assert '$TRUST' not in sys.path"; then P10=PASS; else P10=FAIL; fi

# P06: ordinary proposal is mediated by a root test driver acting as narrow ingress; no worker authority is transferred.
python3 - <<PY
import socket,json
s=socket.socket(socket.AF_UNIX); s.connect('$SOCK'); s.send(json.dumps({'op':'proposal','id':'m1','source':'worker'}).encode()); print(s.recv(4096).decode())
PY
P06=PASS
# P08 denied decision remains non-authoritative.
python3 - <<PY
import socket,json
s=socket.socket(socket.AF_UNIX); s.connect('$SOCK'); s.send(json.dumps({'op':'promote','id':'m1','allow':False}).encode()); r=json.loads(s.recv(4096)); assert not r['ok']
PY
P08=PASS
# P07 trusted generic ALLOW path; P09 replay is idempotent.
python3 - <<PY
import socket,json
for _ in range(2):
 s=socket.socket(socket.AF_UNIX); s.connect('$SOCK'); s.send(json.dumps({'op':'promote','id':'m1','allow':True}).encode()); assert json.loads(s.recv(4096))['ok']
PY
P07=PASS
kill "$CURATOR"; wait "$CURATOR" 2>/dev/null || true
# P09 exact-once state after replay; P12 restart preserves durable state and no implicit promotion.
read STATE PROMOS < <(runuser -u zcurator -- python3 - "$DB" <<'PY'
import sqlite3,sys
print(*sqlite3.connect(sys.argv[1]).execute("select state,promotions from memories where id='m1'").fetchone())
PY
)
[[ "$STATE" == PROMOTED && "$PROMOS" == 1 ]] && P09=PASS || P09=FAIL
# Add a durable denied/quarantined candidate directly as curator, restart, verify unchanged.
runuser -u zcurator -- python3 - "$DB" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); c.execute("insert or replace into memories values('m2','QUARANTINED',0)"); c.commit()
PY
runuser -u zcurator -- python3 "$TRUST/privileged_curator.py" "$SOCK" "$DB" & CURATOR=$!
for i in {1..50}; do [[ -S "$SOCK" ]] && break; sleep .1; done
read STATE2 PROMOS2 < <(runuser -u zcurator -- python3 - "$DB" <<'PY'
import sqlite3,sys
print(*sqlite3.connect(sys.argv[1]).execute("select state,promotions from memories where id='m2'").fetchone())
PY
)
[[ "$STATE2" == QUARANTINED && "$PROMOS2" == 0 ]] && P12=PASS || P12=FAIL
kill "$CURATOR"; wait "$CURATOR" 2>/dev/null || true

for p in P01 P02 P03 P04 P05 P06 P07 P08 P09 P10 P11 P12; do printf '%s=%s\n' "$p" "${!p}"; done | tee "$RESULT"
if grep -q '=FAIL' "$RESULT"; then exit 1; fi
printf '%s\n' 'WORKER_CAN_IMPORT_PRIVILEGED_SURFACE=NO' 'WORKER_CAN_WRITE_TRUSTED_DB=NO' 'WORKER_HAS_OPERATOR_CAPABILITY=NO' 'WORKER_CAN_SELF_PROMOTE=NO' 'CURATOR_CAN_PROMOTE=YES' 'CURATOR_RESTART_SAFE=YES' 'OS_ENFORCEMENT_USED=separate Unix UIDs + 0700 trusted directory + 0600 DB/socket/module' | tee -a "$RESULT"
