import json
import os
import secrets
import string
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from upstash_redis import Redis

app = FastAPI(title="Moon EVS Key Server")

# Locate Redis at import time (Vercel KV / Upstash).
redis = None


def get_redis() -> Redis:
    global redis
    if redis is None:
        redis = Redis.from_env()
    return redis


ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "change-me")

KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I/L


def new_key() -> str:
    groups = []
    for _ in range(4):
        groups.append("".join(secrets.choice(KEY_ALPHABET) for _ in range(4)))
    return "-".join(groups)


def key_hash(key: str) -> str:
    return "lic:" + key


def _redis_get(r: Redis, key: str, field: str):
    v = r.hget(key_hash(key), field)
    return v.decode() if isinstance(v, bytes) else v


class ValidateBody(BaseModel):
    key: str
    hwid: str


class CreateBody(BaseModel):
    days: int = 30
    max_uses: int = 1
    features: dict = {}
    note: str = ""
    token: str


class RevokeBody(BaseModel):
    token: str
    key: str


class UnbindBody(BaseModel):
    token: str
    key: str


class ExtendBody(BaseModel):
    token: str
    key: str
    days: int


@app.get("/")
def root():
    return {"service": "Moon EVS Key Server", "endpoints": ["/validate", "/admin"]}


# ---------------------------------------------------------------------------
# Client-facing
# ---------------------------------------------------------------------------
@app.post("/validate")
def validate(body: ValidateBody):
    try:
        r = get_redis()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"redis: {e}")

    key = body.key.strip().upper()
    if not r.exists(key_hash(key)):
        raise HTTPException(status_code=403, detail="INVALID_KEY")

    revoked = _redis_get(r, key, "revoked")
    if revoked in ("1", 1, "true"):
        raise HTTPException(status_code=403, detail="KEY_REVOKED")

    expires_at = _redis_get(r, key, "expires_at")
    if expires_at:
        try:
            if time.time() > float(expires_at):
                raise HTTPException(status_code=403, detail="KEY_EXPIRED")
        except ValueError:
            pass

    bound_hwid = _redis_get(r, key, "hwid") or ""
    if bound_hwid:
        if bound_hwid != body.hwid:
            raise HTTPException(status_code=403, detail="KEY_BOUND_OTHER")
    else:
        # First activation: bind to this machine, count the use.
        max_uses = int(_redis_get(r, key, "max_uses") or 1)
        use_count = r.incr("lic:uses:" + key)
        if use_count > max_uses:
            raise HTTPException(status_code=403, detail="KEY_LIMIT_REACHED")
        r.hset(key_hash(key), {"hwid": body.hwid})

    features_raw = _redis_get(r, key, "features")
    features = {}
    try:
        features = json.loads(features_raw) if features_raw else {}
    except Exception:
        pass

    return {
        "valid": True,
        "key": key,
        "expires_at": int(float(expires_at)) if expires_at else None,
        "max_uses": int(_redis_get(r, key, "max_uses") or 1),
        "uses": int(r.get("lic:uses:" + key) or 1),
        "features": features,
        "note": _redis_get(r, key, "note") or "",
    }


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
def _authorize(body) -> None:
    if body.token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="BAD_TOKEN")


@app.post("/admin/create")
def admin_create(body: CreateBody):
    _authorize(body)
    r = get_redis()
    k = new_key()
    now = int(time.time())
    pipe = r.pipeline()
    pipe.hset(
        key_hash(k),
        {
            "created_at": now,
            "expires_at": now + body.days * 86400,
            "revoked": "0",
            "max_uses": body.max_uses,
            "hwid": "",
            "features": json.dumps(body.features),
            "note": body.note,
        },
    )
    pipe.sadd("lic:all", k)
    pipe.execute()
    return {"key": k, "expires_at": now + body.days * 86400}


@app.post("/admin/revoke")
def admin_revoke(body: RevokeBody):
    _authorize(body)
    r = get_redis()
    k = body.key.strip().upper()
    if not r.exists(key_hash(k)):
        raise HTTPException(status_code=404, detail="KEY_NOT_FOUND")
    r.hset(key_hash(k), {"revoked": "1"})
    return {"key": k, "revoked": True}


@app.post("/admin/unbind")
def admin_unbind(body: UnbindBody):
    _authorize(body)
    r = get_redis()
    k = body.key.strip().upper()
    if not r.exists(key_hash(k)):
        raise HTTPException(status_code=404, detail="KEY_NOT_FOUND")
    r.hset(key_hash(k), {"hwid": ""})
    return {"key": k, "unbound": True}


@app.post("/admin/extend")
def admin_extend(body: ExtendBody):
    _authorize(body)
    r = get_redis()
    k = body.key.strip().upper()
    if not r.exists(key_hash(k)):
        raise HTTPException(status_code=404, detail="KEY_NOT_FOUND")
    cur = _redis_get(r, k, "expires_at")
    base = max(float(cur), time.time()) if cur else time.time()
    new_exp = int(base) + body.days * 86400
    r.hset(key_hash(k), {"expires_at": new_exp})
    return {"key": k, "expires_at": new_exp}


@app.post("/admin/keys")
def admin_list(body: CreateBody):
    _authorize(body)
    r = get_redis()
    keys = r.smembers("lic:all") or []
    out = []
    for k in keys:
        if isinstance(k, bytes):
            k = k.decode()
        h = r.hgetall(key_hash(k)) or {}
        def g(f):
            v = h.get(f)
            return v.decode() if isinstance(v, bytes) else v
        out.append({
            "key": k,
            "created_at": g("created_at"),
            "expires_at": g("expires_at"),
            "revoked": g("revoked"),
            "max_uses": g("max_uses"),
            "hwid": g("hwid"),
            "features": g("features"),
            "note": g("note"),
        })
    out.sort(key=lambda x: x.get("created_at") or 0, reverse=True)
    return {"keys": out}


# ---------------------------------------------------------------------------
# Simple browser dashboard
# ---------------------------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Key Server Admin</title>
<style>
body{font-family:system-ui;background:#0f1220;color:#e6e6f0;max-width:900px;margin:30px auto;padding:0 16px}
h1{font-size:22px;color:#c9a0ff}
.card{background:#161a2e;border:1px solid #2a2f4d;border-radius:10px;padding:16px;margin:14px 0}
input{background:#0f1220;border:1px solid #3a4060;color:#fff;border-radius:6px;padding:8px;width:300px;margin-right:8px}
button{background:#7c4dff;border:none;color:#fff;border-radius:6px;padding:8px 14px;cursor:pointer;font-weight:600}
button.gray{background:#3a4060}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #232a4a;word-break:break-all}
.bad{color:#ff6b6b}.ok{color:#5ee08b}.rev{color:#ffb454}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
#msg{white-space:pre-wrap;margin-top:8px}
</style>
</head>
<body>
<h1>&#128272; Moon EVS Key Server Admin</h1>
<div class="card"><div class="row">
<input id="tok" placeholder="Admin token" type="password" style="width:220px">
<button class="gray" onclick="load()">Load keys</button>
</div></div>

<div class="card"><h3>Create key</h3>
<div class="row">
<input id="c_days" placeholder="Days (e.g. 30)" type="number" value="30">
<input id="c_uses" placeholder="Max activations (e.g. 1)" type="number" value="1">
<input id="c_note" placeholder="Note / customer">
<input id="c_feat" placeholder='Features JSON e.g. {"trial":true}' style="width:220px">
<button onclick="createKey()">Create</button>
</div></div>

<div id="keys" class="card"></div>
<div id="msg"></div>

<script>
const base = '';
let TOK = '';
function tok(){ return document.getElementById('tok').value || TOK; }
async function api(path, body){
  const r = await fetch(base+path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token:tok(), ...body})});
  const j = await r.json().catch(()=>({}));
  if(!r.ok){ throw (j.detail || ('HTTP '+r.status)); }
  return j;
}
function show(m){ document.getElementById('msg').textContent = m; }
async function createKey(){
  try{
    const j = await api('/admin/create', {
      days:+document.getElementById('c_days').value||30,
      max_uses:+document.getElementById('c_uses').value||1,
      note:document.getElementById('c_note').value,
      features:JSON.parse(document.getElementById('c_feat').value||'{}')
    });
    show('Key created: '+j.key);
    load();
  }catch(e){ show(String(e)); }
}
async function load(){
  try{
    TOK = document.getElementById('tok').value;
    const j = await api('/admin/keys', {});
    render(j.keys);
  }catch(e){ show(String(e)); }
}
function render(keys){
  let html = '<h3>Keys ('+keys.length+')</h3><table><tr><th>Key</th><th>Created</th><th>Expires</th><th>Status</th><th>HWID</th><th>Note</th><th>Actions</th></tr>';
  for(const k of keys){
    const exp = k.expires_at ? new Date(k.expires_at*1000).toLocaleString() : 'never';
    const now = Date.now()/1000;
    let st, cls;
    if(k.revoked==='1'){ st='REVOKED'; cls='rev'; }
    else if(k.expires_at && now>k.expires_at){ st='EXPIRED'; cls='bad'; }
    else { st='ACTIVE'; cls='ok'; }
    const hwid = (k.hwid||'').slice(0,10)+'...';
    html += '<tr><td>'+k.key+'</td><td>'+new Date((k.created_at||0)*1000).toLocaleString()+'</td><td>'+exp+'</td>'
      +'<td class="'+cls+'">'+st+'</td><td>'+hwid+'</td><td>'+(k.note||'')+'</td>'
      +'<td><button class="gray" onclick="doRevoke(\''+k.key+'\')">Revoke</button> '
      +'<button class="gray" onclick="doUnbind(\''+k.key+'\')">Unbind</button> '
      +'<button class="gray" onclick="doExtend(\''+k.key+'\',30)">+30d</button></td></tr>';
  }
  document.getElementById('keys').innerHTML = html+'</table>';
}
async function doRevoke(key){ try{ await api('/admin/revoke',{key}); load(); }catch(e){ show(String(e)); } }
async function doUnbind(key){ try{ await api('/admin/unbind',{key}); load(); }catch(e){ show(String(e)); } }
async function doExtend(key,days){ try{ await api('/admin/extend',{key,days}); load(); }catch(e){ show(String(e)); } }
</script>
</body>
</html>
"""


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return DASHBOARD_HTML