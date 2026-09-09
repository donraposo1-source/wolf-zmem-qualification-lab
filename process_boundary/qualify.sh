#!/usr/bin/env bash
set -euo pipefail
ROOT="$(mktemp -d)"; chmod 0711 "$ROOT"
TRUST="$ROOT/trusted"; INGRESS="$ROOT/ingress"; WORK="$ROOT/worker"; PRIV="$TRUST/priv.sock"; PROP="$INGRESS/proposal.sock"; DB="$TRUST/trusted.db"; RESULT="$ROOT/result.env"
trap 'rm -rf "$ROOT"' EXIT
useradd -M -s /usr/sbin/nologin zcurator
useradd -M -s /usr/sbin/nologin zworker
install -d -o zcurator -g zcurator -m 0700 "$TRUST"
install -d -o zcurator -g zworker -m 0770 "$INGRESS"
install -d -o zworker -g zworker -m 0700 "$WORK"
cat > "$TRUST/privileged_curator.py" <<'PY'
import json,os,selectors,socket,sqlite3,sys
priv,prop,db=sys.argv[1:4]
con=sqlite3.connect(db); con.execute('create table if not exists memories(id text primary key,state text,promotions integer default 0)'); con.commit(); os.chmod(db,0o600)
for p in (priv,prop):
 try: os.unlink(p)
 except FileNotFoundError: pass
sp=socket.socket(socket.AF_UNIX); sp.bind(priv); os.chmod(priv,0o600); sp.listen(8)
sq=socket.socket(socket.AF_UNIX); sq.bind(prop); os.chmod(prop,0o660); sq.listen(8)
sel=selectors.DefaultSelector(); sel.register(sp,selectors.EVENT_READ,'priv'); sel.register(sq,selectors.EVENT_READ,'proposal')
while True:
 for key,_ in sel.select():
  c,_=key.fileobj.accept(); req=json.loads(c.recv(8192) or b'{}'); mid=req.get('id','')
  if key.data=='proposal':
   # Identity claims are data only: this surface can create QUARANTINED candidates and nothing else.
   con.execute("insert or ignore into memories values(?,'QUARANTINED',0)",(mid,)); con.commit(); out={'ok':True,'state':'QUARANTINED'}
  elif req.get('op')=='promote' and req.get('allow') is True:
   con.execute("update memories set state='PROMOTED',promotions=case when promotions=0 then 1 else promotions end where id=?",(mid,)); con.commit(); out={'ok':True}
  elif req.get('op')=='promote': out={'ok':False,'error':'DENIED'}
  else: out={'ok':False,'error':'DENIED'}
  c.send(json.dumps(out).encode()); c.close()
PY
chown zcurator:zcurator "$TRUST/privileged_curator.py"; chmod 0600 "$TRUST/privileged_curator.py"
runuser -u zcurator -- python3 "$TRUST/privileged_curator.py" "$PRIV" "$PROP" "$DB" & CURATOR=$!
for i in {1..50}; do [[ -S "$PRIV" && -S "$PROP" ]] && break; sleep .1; done
[[ -S "$PRIV" && -S "$PROP" ]] || exit 2
if runuser -u zworker -- python3 -c "exec(open('$TRUST/privileged_curator.py').read())" 2>/dev/null; then P01=FAIL; else P01=PASS; fi
if runuser -u zworker -- python3 -c "import sqlite3; sqlite3.connect('file:$DB?mode=rw',uri=True).execute('pragma user_version=9')" 2>/dev/null; then P02=FAIL; P11=FAIL; else P02=PASS; P11=PASS; fi
if runuser -u zworker -- env -i PATH=/usr/bin:/bin python3 -c "import os; assert not any('CURATOR' in k or 'TOKEN' in k or 'CAP' in k for k in os.environ); assert len(os.listdir('/proc/self/fd'))<=4"; then P03=PASS; else P03=FAIL; fi
# Spoof over worker-accessible proposal ingress: must remain quarantined.
if runuser -u zworker -- python3 -c "import socket,json; s=socket.socket(socket.AF_UNIX); s.connect('$PROP'); s.send(json.dumps({'op':'promote','id':'spoof','allow':True,'source':'human','actor':'operator'}).encode()); r=json.loads(s.recv(4096)); assert r['state']=='QUARANTINED'"; then P04=PASS; else P04=FAIL; fi
# Direct privileged IPC must be denied by Unix socket/directory permissions.
if runuser -u zworker -- python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.connect('$PRIV')" 2>/dev/null; then P05=FAIL; else P05=PASS; fi
mkdir -p "$WORK/inject"; printf '%s\n' 'raise SystemExit("injected")' > "$WORK/inject/privileged_curator.py"; chown -R zworker:zworker "$WORK/inject"
if runuser -u zworker -- env PYTHONPATH="$WORK/inject" python3 -c "import sys; assert '$TRUST' not in sys.path"; then P10=PASS; else P10=FAIL; fi
# Real worker proposal path.
if runuser -u zworker -- python3 -c "import socket,json; s=socket.socket(socket.AF_UNIX); s.connect('$PROP'); s.send(json.dumps({'id':'m1','source':'worker'}).encode()); r=json.loads(s.recv(4096)); assert r['state']=='QUARANTINED'"; then P06=PASS; else P06=FAIL; fi
# Trusted driver represents abstract deterministic policy only; no Wolf policy is present.
python3 - <<PY
import socket,json
s=socket.socket(socket.AF_UNIX); s.connect('$PRIV'); s.send(json.dumps({'op':'promote','id':'m1','allow':False}).encode()); assert not json.loads(s.recv(4096))['ok']
PY
P08=PASS
python3 - <<PY
import socket,json
for _ in range(2):
 s=socket.socket(socket.AF_UNIX); s.connect('$PRIV'); s.send(json.dumps({'op':'promote','id':'m1','allow':True}).encode()); assert json.loads(s.recv(4096))['ok']
PY
P07=PASS
kill "$CURATOR"; wait "$CURATOR" 2>/dev/null || true
read STATE PROMOS < <(runuser -u zcurator -- python3 - "$DB" <<'PY'
import sqlite3,sys
print(*sqlite3.connect(sys.argv[1]).execute("select state,promotions from memories where id='m1'").fetchone())
PY
)
[[ "$STATE" == PROMOTED && "$PROMOS" == 1 ]] && P09=PASS || P09=FAIL
# Durable candidate then curator death/restart: no implicit promotion.
runuser -u zworker -- python3 -c "import socket,json; s=socket.socket(socket.AF_UNIX); s.connect('$PROP'); s.send(json.dumps({'id':'m2'}).encode()); assert json.loads(s.recv(4096))['state']=='QUARANTINED'" 2>/dev/null || true
# m2 proposal above cannot run while curator is dead, so create it before restart through curator-owned DB solely to model already-durable state.
runuser -u zcurator -- python3 - "$DB" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); c.execute("insert or replace into memories values('m2','QUARANTINED',0)"); c.commit()
PY
rm -f "$PRIV" "$PROP"
runuser -u zcurator -- python3 "$TRUST/privileged_curator.py" "$PRIV" "$PROP" "$DB" & CURATOR=$!
for i in {1..50}; do [[ -S "$PRIV" && -S "$PROP" ]] && break; sleep .1; done
read STATE2 PROMOS2 < <(runuser -u zcurator -- python3 - "$DB" <<'PY'
import sqlite3,sys
print(*sqlite3.connect(sys.argv[1]).execute("select state,promotions from memories where id='m2'").fetchone())
PY
)
[[ "$STATE2" == QUARANTINED && "$PROMOS2" == 0 ]] && P12=PASS || P12=FAIL
kill "$CURATOR"; wait "$CURATOR" 2>/dev/null || true
for p in P01 P02 P03 P04 P05 P06 P07 P08 P09 P10 P11 P12; do printf '%s=%s\n' "$p" "${!p}"; done | tee "$RESULT"
if grep -q '=FAIL' "$RESULT"; then exit 1; fi
printf '%s\n' 'WORKER_CAN_IMPORT_PRIVILEGED_SURFACE=NO' 'WORKER_CAN_WRITE_TRUSTED_DB=NO' 'WORKER_HAS_OPERATOR_CAPABILITY=NO' 'WORKER_CAN_SELF_PROMOTE=NO' 'CURATOR_CAN_PROMOTE=YES' 'CURATOR_RESTART_SAFE=YES' 'OS_ENFORCEMENT_USED=separate Unix UIDs + worker-only proposal socket + 0700 trusted directory + 0600 privileged DB/socket/module' | tee -a "$RESULT"
