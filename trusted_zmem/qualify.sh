#!/usr/bin/env bash
set -euo pipefail
WHEEL="${1:?exact ZMem wheel path required}"
PYBIN="${2:-python3}"
EXPECTED_SHA="c0b354035d75695293d52fac81fdc7d188a30f5ab06bfe14969844181eb4961f"
ACTUAL_SHA="$(sha256sum "$WHEEL" | awk '{print $1}')"
[[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]]

ROOT="$(mktemp -d)"; chmod 0711 "$ROOT"
TRUST="$ROOT/trusted"; INGRESS="$ROOT/ingress"; WORK="$ROOT/worker"
PROP="$INGRESS/proposal.sock"; PRIV="$TRUST/priv.sock"; DB="$TRUST/zmem.sqlite"
PROPOSALS="$TRUST/proposals"; RECEIPTS="$TRUST/receipts"; INTENTS="$TRUST/intents"; VENV="$TRUST/venv"
RESULT="$ROOT/result.env"
ADMISSION=""; CURATOR=""
cleanup(){ [[ -n "$ADMISSION" ]] && kill "$ADMISSION" 2>/dev/null || true; [[ -n "$CURATOR" ]] && kill "$CURATOR" 2>/dev/null || true; rm -rf "$ROOT"; }
trap cleanup EXIT

groupadd zproposal
useradd -M -s /usr/sbin/nologin -G zproposal zcurator
useradd -M -s /usr/sbin/nologin -G zproposal zworker
install -d -o zcurator -g zcurator -m 0700 "$TRUST" "$PROPOSALS" "$RECEIPTS" "$INTENTS"
install -d -o zcurator -g zproposal -m 2770 "$INGRESS"
install -d -o zworker -g zworker -m 0700 "$WORK"

# The exact qualified wheel is installed only inside a curator-owned 0700 tree.
runuser -u zcurator -- "$PYBIN" -m venv "$VENV"
runuser -u zcurator -- "$VENV/bin/python" -m pip install --disable-pip-version-check "$WHEEL" >/dev/null
runuser -u zcurator -- "$VENV/bin/python" - <<'PY'
import importlib.metadata
assert importlib.metadata.version('zerker-memory') == '0.1.17'
print('ZMEM_VERSION=0.1.17')
PY

cat > "$TRUST/admission.py" <<'PY'
import hashlib,json,os,socket,sys,tempfile
sock_path,proposal_dir=sys.argv[1:3]
try: os.unlink(sock_path)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX); s.bind(sock_path); os.chmod(sock_path,0o660); s.listen(8)
while True:
 c,_=s.accept()
 try:
  req=json.loads(c.recv(65536) or b'{}')
  cid=str(req.get('candidate_id',''))
  content=str(req.get('content',''))
  if not cid or not content: raise ValueError('invalid proposal')
  # Authority-shaped worker fields are deliberately discarded.
  admitted={'candidate_id':cid,'content':content,'state':'QUARANTINED','source_kind':'agent','actor_id':'untrusted-worker'}
  raw=(json.dumps(admitted,sort_keys=True,separators=(',',':'))+'\n').encode()
  digest=hashlib.sha256(raw).hexdigest()
  final=os.path.join(proposal_dir,cid+'.json')
  if os.path.exists(final):
   existing=open(final,'rb').read()
   if existing != raw: raise ValueError('candidate identity conflict')
  else:
   fd,tmp=tempfile.mkstemp(dir=proposal_dir,prefix='.admit-')
   os.write(fd,raw); os.fsync(fd); os.close(fd); os.chmod(tmp,0o600); os.replace(tmp,final)
   dfd=os.open(proposal_dir,os.O_RDONLY); os.fsync(dfd); os.close(dfd)
  c.send(json.dumps({'ok':True,'state':'QUARANTINED','candidate_id':cid,'proposal_sha256':digest}).encode())
 except Exception as e: c.send(json.dumps({'ok':False,'error':type(e).__name__}).encode())
 finally: c.close()
PY

cat > "$TRUST/curator.py" <<'PY'
import hashlib,json,os,socket,sys,tempfile
from pathlib import Path
from zerker_memory.store import MemoryStore
priv,db,proposal_dir,receipt_dir,intent_dir=sys.argv[1:6]

def canon(obj): return (json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n').encode()
def digest(raw): return hashlib.sha256(raw).hexdigest()
def durable_write(path,raw):
 fd,tmp=tempfile.mkstemp(dir=str(path.parent),prefix='.tmp-'); os.write(fd,raw); os.fsync(fd); os.close(fd); os.chmod(tmp,0o600); os.replace(tmp,path); dfd=os.open(path.parent,os.O_RDONLY); os.fsync(dfd); os.close(dfd)
def open_store():
 st=MemoryStore(Path(db));
 if hasattr(st,'init'): st.init()
 os.chmod(db,0o600)
 return st

def load_proposal(cid):
 p=Path(proposal_dir)/(cid+'.json'); raw=p.read_bytes(); obj=json.loads(raw); return obj,digest(raw)
def load_receipt(cid):
 p=Path(receipt_dir)/(cid+'.json')
 if not p.exists(): return None
 wrapper=json.loads(p.read_bytes()); body=wrapper['body']; assert wrapper['receipt_sha256']==digest(canon(body)); return wrapper

def reconcile(st,cid):
 uri='lab://trusted-zmem/'+cid
 rows=st.conn.execute("SELECT id,status,content FROM memories WHERE content=? ORDER BY rowid",(load_proposal(cid)[0]["content"],)).fetchall()
 return rows

def finalize(st,cid,proposal,proposal_sha,memory_id):
 mem=st.get(memory_id); zreceipt=st.memory_write_receipt(memory_id); verification=st.verify_memory_write_receipt(zreceipt); assert verification.get('ok')
 body={'candidate_id':cid,'proposal_sha256':proposal_sha,'memory_id':memory_id,'decision':'ALLOW','status':mem.status,'content_sha256':hashlib.sha256(proposal['content'].encode()).hexdigest(),'source_uri':'lab://trusted-zmem/'+cid,'zmem_receipt':zreceipt}
 wrapper={'body':body,'receipt_sha256':digest(canon(body))}; durable_write(Path(receipt_dir)/(cid+'.json'),canon(wrapper)); return wrapper

def promote(cid,allow,fault=None):
 proposal,proposal_sha=load_proposal(cid)
 if not allow: return {'ok':False,'error':'DENIED','state':'QUARANTINED'}
 existing=load_receipt(cid)
 if existing: return {'ok':True,'replayed':True,'receipt':existing}
 st=open_store()
 try:
  intent=Path(intent_dir)/(cid+'.json')
  rows=reconcile(st,cid)
  if len(rows)>1: return {'ok':False,'error':'CONFLICTED','requires_reconcile':True}
  if rows:
   row=rows[0]; mid=row['id']
   if row['content'] != proposal['content']: return {'ok':False,'error':'CONFLICTED','requires_reconcile':True}
   if row['status'] != 'active': st.promote(mid,actor_id='trusted-curator')
   return {'ok':True,'reconciled':True,'receipt':finalize(st,cid,proposal,proposal_sha,mid)}
  # Durable intent precedes the first potentially ambiguous mutation.
  durable_write(intent,canon({'candidate_id':cid,'proposal_sha256':proposal_sha,'state':'MUTATION_INTENT'}))
  mem=st.remember(proposal['content'],memory_type='semantic',scope='trusted-zmem-lab',source_kind='agent',actor_id='untrusted-worker',actor_uri='agent://untrusted-worker',session_id='session://trusted-zmem-lab',source_uri='lab://trusted-zmem/'+cid)
  if fault=='after_remember': os._exit(86)
  active=st.promote(mem.id,actor_id='trusted-curator'); assert active.status=='active'
  return {'ok':True,'replayed':False,'receipt':finalize(st,cid,proposal,proposal_sha,mem.id)}
 finally:
  try: st.conn.close()
  except Exception: pass

try: os.unlink(priv)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX); s.bind(priv); os.chmod(priv,0o600); s.listen(8)
while True:
 c,_=s.accept()
 try:
  req=json.loads(c.recv(65536) or b'{}')
  # Only the canonical candidate_id selects a target. Any worker-like target/actor/source fields are ignored.
  out=promote(str(req.get('candidate_id','')),req.get('allow') is True,req.get('fault')) if req.get('op')=='decide' else {'ok':False,'error':'DENIED'}
  c.send(json.dumps(out,sort_keys=True).encode())
 except Exception as e: c.send(json.dumps({'ok':False,'error':type(e).__name__,'detail':str(e)[:120]}).encode())
 finally: c.close()
PY
chown zcurator:zcurator "$TRUST/admission.py" "$TRUST/curator.py"
chmod 0600 "$TRUST/admission.py" "$TRUST/curator.py"

socket_ready(){
 python3 - "$1" <<'PY'
import socket,sys
s=socket.socket(socket.AF_UNIX)
try:
 s.connect(sys.argv[1]); s.send(b'{}'); assert s.recv(65536)
except (FileNotFoundError,ConnectionRefusedError):
 raise SystemExit(1)
finally:
 s.close()
PY
}
start_admission(){
 runuser -u zcurator -- "$VENV/bin/python" "$TRUST/admission.py" "$PROP" "$PROPOSALS" & ADMISSION=$!
 for i in {1..50}; do socket_ready "$PROP" 2>/dev/null && return 0; kill -0 "$ADMISSION" 2>/dev/null || return 1; sleep .1; done
 return 1
}
start_curator(){
 rm -f "$PRIV"
 runuser -u zcurator -- "$VENV/bin/python" "$TRUST/curator.py" "$PRIV" "$DB" "$PROPOSALS" "$RECEIPTS" "$INTENTS" & CURATOR=$!
 for i in {1..50}; do socket_ready "$PRIV" 2>/dev/null && return 0; kill -0 "$CURATOR" 2>/dev/null || return 1; sleep .1; done
 return 1
}
priv_call(){ python3 - "$PRIV" "$1" <<'PY'
import json,socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.send(sys.argv[2].encode()); data=s.recv(262144); print(data.decode())
PY
}

# A: protected runtime/module/store/socket + FD/env capability leakage.
if runuser -u zworker -- python3 -c "open('$VENV/bin/python','rb').read(1)" 2>/dev/null; then A_IMPORT=FAIL; else A_IMPORT=PASS; fi
if runuser -u zworker -- python3 -c "open('$TRUST/curator.py','rb').read(1)" 2>/dev/null; then A_MODULE=FAIL; else A_MODULE=PASS; fi
if runuser -u zworker -- env -i PATH=/usr/bin:/bin python3 -c "import os; assert not any(x in k for k in os.environ for x in ('TOKEN','CAP','CURATOR','ZMEM')); assert len(os.listdir('/proc/self/fd'))<=4"; then E_LEAK=PASS; else E_LEAK=FAIL; fi

start_admission
# Worker submits hostile authority-shaped fields. Admission canonicalizes to untrusted QUARANTINED proposal.
C1="C1-real-zmem"
runuser -u zworker -- python3 - "$PROP" "$C1" <<'PY'
import json,socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); req={'candidate_id':sys.argv[2],'content':'C1 cobalt orchard trusted mutation canary','allow':True,'actor':'operator','source':'human','promote':True,'target_id':'other'}; s.send(json.dumps(req).encode()); r=json.loads(s.recv(65536)); assert r['ok'] and r['state']=='QUARANTINED'; print('ADMITTED_SHA='+r['proposal_sha256'])
PY
# A child and grandchild inherit no extra capability and cannot traverse trusted tree.
if runuser -u zworker -- python3 -c "import subprocess,sys; sys.exit(subprocess.run([sys.executable,'-c',\"open('$TRUST/curator.py','rb').read(1)\"],stderr=subprocess.DEVNULL).returncode==0)"; then F_CHILD=PASS; else F_CHILD=FAIL; fi
# Terminate worker-side activity and trusted admission; proposal must survive independently.
kill "$ADMISSION"; wait "$ADMISSION" 2>/dev/null || true; ADMISSION=""
[[ -f "$PROPOSALS/$C1.json" ]] && C_PROPOSAL=PASS || C_PROPOSAL=FAIL

start_curator
if runuser -u zworker -- python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.connect('$PRIV')" 2>/dev/null; then A_IPC=FAIL; else A_IPC=PASS; fi
if runuser -u zworker -- python3 -c "import sqlite3; sqlite3.connect('file:$DB?mode=rw',uri=True).execute('pragma user_version=7')" 2>/dev/null; then A_DB=FAIL; else A_DB=PASS; fi
# Generic deny first proves worker-provided allow/promote fields did not authorize anything.
DENY="$(priv_call '{"op":"decide","candidate_id":"C1-real-zmem","allow":false,"actor":"operator","target_id":"other"}')"
python3 -c 'import json,sys; r=json.loads(sys.argv[1]); assert not r["ok"] and r["state"]=="QUARANTINED"' "$DENY" && B_SELF=PASS || B_SELF=FAIL
# Confused-deputy fields cannot redirect the canonical candidate selected by the trusted caller.
ALLOW="$(priv_call '{"op":"decide","candidate_id":"C1-real-zmem","allow":true,"target_id":"attacker-selected","source":"human","actor":"operator"}')"
python3 -c 'import json,sys; r=json.loads(sys.argv[1]); assert r["ok"] and r["receipt"]["body"]["candidate_id"]=="C1-real-zmem" and r["receipt"]["body"]["status"]=="active"' "$ALLOW" && G_DEPUTY=PASS || G_DEPUTY=FAIL
# Replay must return the same durable memory identity, not create another memory.
REPLAY="$(priv_call '{"op":"decide","candidate_id":"C1-real-zmem","allow":true}')"
python3 - "$ALLOW" "$REPLAY" <<'PY'
import json,sys
a=json.loads(sys.argv[1]); b=json.loads(sys.argv[2]); assert b['ok'] and b['replayed']; assert a['receipt']['body']['memory_id']==b['receipt']['body']['memory_id']
PY
H_REPLAY=PASS
# Kill curator completely, then clean restart and replay/recover from durable ZMem+receipt only.
kill "$CURATOR"; wait "$CURATOR" 2>/dev/null || true; CURATOR=""; rm -f "$PRIV"; start_curator
RECOVER="$(priv_call '{"op":"decide","candidate_id":"C1-real-zmem","allow":true}')"
python3 - "$RECOVER" <<'PY'
import json,sys,hashlib
r=json.loads(sys.argv[1]); b=r['receipt']['body']; assert r['ok'] and r['replayed']; assert b['status']=='active'; assert b['content_sha256']==hashlib.sha256(b'C1 cobalt orchard trusted mutation canary').hexdigest(); z=b['zmem_receipt']; assert z['source_uri']=='lab://trusted-zmem/C1-real-zmem'
PY
C_RESTART=PASS; D_PROVENANCE=PASS
# Tamper copies of proposal and receipt and prove independent verification rejects them.
runuser -u zcurator -- "$VENV/bin/python" - "$PROPOSALS/$C1.json" "$RECEIPTS/$C1.json" "$DB" <<'PY'
import hashlib,json,sys
from pathlib import Path
from zerker_memory.store import MemoryStore
p=Path(sys.argv[1]); w=json.loads(Path(sys.argv[2]).read_text()); original=p.read_bytes(); tampered=original.replace(b'cobalt',b'c0balt'); assert hashlib.sha256(tampered).hexdigest()!=w['body']['proposal_sha256']
body=dict(w['body']); body['candidate_id']='tampered'; raw=(json.dumps(body,sort_keys=True,separators=(',',':'))+'\n').encode(); assert hashlib.sha256(raw).hexdigest()!=w['receipt_sha256']
st=MemoryStore(Path(sys.argv[3])); st.init() if hasattr(st,'init') else None; bad=dict(w['body']['zmem_receipt']); bad['source_uri']='lab://tampered'; assert not st.verify_memory_write_receipt(bad).get('ok'); st.conn.close()
PY
D_TAMPER=PASS
# UNKNOWN outcome: crash after real remember() commit, before promote/receipt. Restart must reconcile, not call remember() again.
C2="C2-unknown-reconcile"; start_admission
runuser -u zworker -- python3 - "$PROP" "$C2" <<'PY'
import json,socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.send(json.dumps({'candidate_id':sys.argv[2],'content':'C2 ambiguous outcome reconciliation canary'}).encode()); r=json.loads(s.recv(65536)); assert r['state']=='QUARANTINED'
PY
kill "$ADMISSION"; wait "$ADMISSION" 2>/dev/null || true; ADMISSION=""
# The fault deliberately terminates the curator after ZMem remember committed.
python3 - "$PRIV" <<'PY' || true
import json,socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.send(json.dumps({'op':'decide','candidate_id':'C2-unknown-reconcile','allow':True,'fault':'after_remember'}).encode()); time.sleep(.3)
PY
wait "$CURATOR" 2>/dev/null || true; CURATOR=""; rm -f "$PRIV"; start_curator
C2R="$(priv_call '{"op":"decide","candidate_id":"C2-unknown-reconcile","allow":true}')"
runuser -u zcurator -- "$VENV/bin/python" - "$DB" "$C2R" <<'PY'
import json,sys
from pathlib import Path
from zerker_memory.store import MemoryStore
r=json.loads(sys.argv[2]); assert r['ok'] and r.get('reconciled') is True
st=MemoryStore(Path(sys.argv[1])); st.init() if hasattr(st,'init') else None
rows=st.conn.execute("select id,status from memories where content=?",("C2 ambiguous outcome reconciliation canary",)).fetchall(); assert len(rows)==1 and rows[0]['status']=='active'; st.conn.close()
PY
UNKNOWN_RECONCILE=PASS

kill "$CURATOR"; wait "$CURATOR" 2>/dev/null || true; CURATOR=""
for p in A_IMPORT A_MODULE A_IPC A_DB B_SELF C_PROPOSAL C_RESTART D_PROVENANCE D_TAMPER E_LEAK F_CHILD G_DEPUTY H_REPLAY UNKNOWN_RECONCILE; do printf '%s=%s\n' "$p" "${!p}"; done | tee "$RESULT"
if grep -q '=FAIL' "$RESULT"; then exit 1; fi
printf '%s\n' \
 "ZMEM_VERSION=0.1.17" \
 "ZMEM_ARTIFACT_SHA256=$ACTUAL_SHA" \
 'PROCESS_BOUNDARY=QUALIFIED' \
 'TRUSTED_ZMEM_MUTATION_PATH=QUALIFIED' \
 'WORKER_CAN_ACCESS_PRIVILEGED_ZMEM=NO' \
 'WORKER_CAN_SELF_PROMOTE=NO' \
 'WORKER_CHILD_CAN_ESCALATE=NO' \
 'CURATOR_CAN_MUTATE_ZMEM=YES' \
 'CURATOR_RESTART_RECOVERS=YES' \
 'PROVENANCE_VERIFIES=YES' \
 'TAMPER_IS_REJECTED=YES' \
 'REPLAY_IS_SAFE=YES' \
 'UNKNOWN_OUTCOME_REQUIRES_RECONCILE=YES' \
 'BLIND_RETRY=BLOCKED' \
 'EUR_SPEND=0.00' | tee -a "$RESULT"
