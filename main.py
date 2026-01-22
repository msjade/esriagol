import os, json, time, pathlib, secrets
from typing import Dict, Any, Optional, List

import httpx
from fastapi import FastAPI, HTTPException, Query, Header, Response
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

APP_TITLE = "AGOL Secure Overlay + Attributes Proxy"

SERVICES_CONFIG = os.getenv("SERVICES_CONFIG", "services.json")
CLIENTS_CONFIG = os.getenv("CLIENTS_CONFIG", "clients.json")
PUBLIC_PROXY_BASE = os.getenv("PUBLIC_PROXY_BASE", "").rstrip("/")

# Admin endpoints protection
ADMIN_KEY = os.getenv("ADMIN_KEY", "").strip()  # required for /admin endpoints


# ----------------------------
# Config loaders
# ----------------------------
def load_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise HTTPException(500, f"Missing config file: {path}")
    except json.JSONDecodeError as e:
        raise HTTPException(500, f"Invalid JSON in {path}: {e}")


def write_json_atomic(path: str, data: Dict[str, Any]) -> None:
    """
    Atomically write JSON to disk to reduce risk of partial writes.
    """
    p = pathlib.Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(p)


def load_services() -> Dict[str, Any]:
    return load_json(SERVICES_CONFIG)


def load_clients() -> Dict[str, Any]:
    return load_json(CLIENTS_CONFIG)


def require_public_base():
    if not PUBLIC_PROXY_BASE:
        raise HTTPException(500, "Set PUBLIC_PROXY_BASE (e.g. https://proxy.yourdomain.com)")


# ----------------------------
# Admin key enforcement
# ----------------------------
def require_admin(x_admin_key: Optional[str], admin_key_qs: Optional[str]) -> None:
    """
    Admin endpoints are protected by ADMIN_KEY.
    Accept either:
      - x-admin-key header
      - ?admin_key= query param
    """
    if not ADMIN_KEY:
        raise HTTPException(500, "Server misconfig: ADMIN_KEY not set")
    provided = (x_admin_key or admin_key_qs or "").strip()
    if provided != ADMIN_KEY:
        raise HTTPException(401, "Unauthorized: invalid admin key")


# ----------------------------
# Client key enforcement
# ----------------------------
def get_client_record(client_key: str) -> Dict[str, Any]:
    clients = load_clients().get("clients", {})
    rec = clients.get(client_key)
    if not rec:
        raise HTTPException(401, "Unauthorized: invalid key")
    if rec.get("disabled") is True:
        raise HTTPException(401, "Unauthorized: key disabled")
    return rec


def enforce_access(alias: str, x_api_key: Optional[str], key: Optional[str]) -> Dict[str, Any]:
    """
    Accept either:
      - x-api-key header (recommended for /v1 endpoints)
      - ?key= query parameter (recommended for tile endpoints)
    """
    client_key = (x_api_key or key or "").strip()
    if not client_key:
        raise HTTPException(401, "Unauthorized: missing key")

    rec = get_client_record(client_key)

    allowed = rec.get("services", [])
    if allowed and alias not in allowed:
        raise HTTPException(403, "Forbidden: service not allowed for this key")

    return rec


# ----------------------------
# AGOL Token caching
# ----------------------------
class TokenCache:
    def __init__(self):
        self.token: Optional[str] = None
        self.expires_at: float = 0.0  # epoch seconds

    def valid(self) -> bool:
        return bool(self.token) and time.time() < (self.expires_at - 60)


TOKEN_CACHE = TokenCache()


async def get_agol_token(cfg: Dict[str, Any]) -> str:
    """
    Generate AGOL token using username/password:
      POST https://www.arcgis.com/sharing/rest/generateToken
    """
    if TOKEN_CACHE.valid():
        return TOKEN_CACHE.token  # type: ignore

    auth = cfg.get("auth", {})
    if auth.get("type") != "generateToken":
        raise HTTPException(500, "Unsupported auth.type (expected generateToken)")

    portal = auth.get("portal", "https://www.arcgis.com").rstrip("/")
    token_url = f"{portal}/sharing/rest/generateToken"

    username = os.getenv(auth.get("username_env", "AGOL_USERNAME"), "")
    password = os.getenv(auth.get("password_env", "AGOL_PASSWORD"), "")
    referer = auth.get("referer", "https://www.arcgis.com")

    if not username or not password:
        raise HTTPException(500, "Missing AGOL credentials env vars")

    data = {
        "f": "json",
        "username": username,
        "password": password,
        "client": "referer",
        "referer": referer,
        "expiration": "60",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(token_url, data=data)
        j = r.json()

    if "error" in j:
        raise HTTPException(500, f"AGOL token error: {j['error']}")

    token = j.get("token")
    expires_ms = j.get("expires")
    if not token or not expires_ms:
        raise HTTPException(500, "AGOL token response missing token/expires")

    TOKEN_CACHE.token = token
    TOKEN_CACHE.expires_at = float(expires_ms) / 1000.0
    return token


# ----------------------------
# Query safety helpers
# ----------------------------
def sanitize_outfields(requested: Optional[str], allowed: List[str]) -> str:
    # Always restrict to allowed list
    if not requested or requested.strip() == "*":
        return ",".join(allowed)
    fields = [f.strip() for f in requested.split(",") if f.strip()]
    safe = [f for f in fields if f in allowed]
    return ",".join(safe) if safe else ",".join(allowed)


def apply_where_lock(client_rec: Dict[str, Any], alias: str, where: str) -> str:
    """
    Optional per-client restriction (e.g., STATE_NAME='Kwara').
    If configured, proxy will AND it to every where clause.
    """
    lock_map = client_rec.get("where_lock", {}) or {}
    lock = lock_map.get(alias)
    if not lock:
        return where
    return f"({where}) AND ({lock})"


app = FastAPI(title=APP_TITLE)

# ✅ CORS so your HTML/JS apps can call /identify and /query
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # tighten later to specific client domains if you want
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {"ok": True, "message": "AGOL proxy running. Try /health or /admin-ui"}


@app.get("/health")
def health():
    return {"ok": True, "service": APP_TITLE}


# -----------------------------
# Simple Admin UI (so /admin-ui won't 404)
# -----------------------------
from fastapi.responses import HTMLResponse

from fastapi.responses import HTMLResponse

@app.get("/admin-ui", response_class=HTMLResponse)
def admin_ui():
    return r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>AGOL Secure Proxy — Admin (OpenLayers)</title>

  <!-- OpenLayers -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/ol@9.2.4/ol.css">
  <script src="https://cdn.jsdelivr.net/npm/ol@9.2.4/dist/ol.js"></script>

  <style>
    :root{
      --bg:#070a12; --panel:rgba(15,23,42,.72); --line:rgba(148,163,184,.18);
      --text:rgba(226,232,240,.92); --muted:rgba(148,163,184,.85);
      --shadow:0 30px 80px rgba(0,0,0,.55); --r:18px;
      --btn:rgba(30,41,59,.8); --btn2:rgba(2,6,23,.35);
    }
    *{box-sizing:border-box}
    body{
      margin:0;height:100vh;overflow:hidden;color:var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: radial-gradient(1000px 600px at 70% -10%, rgba(59,130,246,.15), transparent 55%),
                  radial-gradient(900px 500px at -10% 40%, rgba(34,197,94,.12), transparent 55%),
                  var(--bg);
    }
    .app{display:grid;grid-template-columns:420px 1fr;gap:14px;height:100vh;padding:14px}
    .sidebar{display:flex;flex-direction:column;gap:12px;overflow:auto;padding-right:6px}
    .card{
      background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
      box-shadow:var(--shadow);padding:16px;backdrop-filter:blur(10px)
    }
    .title{font-size:20px;font-weight:700;margin:0 0 8px}
    .tabs{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 12px}
    .tabbtn{
      padding:8px 12px;border-radius:999px;border:1px solid var(--line);
      background:var(--btn2);color:var(--text);cursor:pointer;font-size:13px
    }
    .tabbtn.active{background:rgba(30,41,59,.95);border-color:rgba(148,163,184,.25)}
    .section{display:none}.section.active{display:block}
    .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    label{display:block;font-size:12px;color:var(--muted);margin:10px 0 6px}
    input, textarea{
      width:100%;padding:12px;border-radius:14px;border:1px solid rgba(148,163,184,.20);
      background:rgba(2,6,23,.35);color:var(--text);outline:none
    }
    textarea{min-height:92px;resize:vertical}
    .btn{
      padding:12px 14px;border-radius:14px;border:1px solid rgba(148,163,184,.20);
      background:var(--btn);color:var(--text);cursor:pointer;font-weight:600;min-width:160px
    }
    .btn.primary{background:rgba(59,130,246,.18)}
    .btn.good{background:rgba(34,197,94,.14)}
    .btn.full{width:100%}
    pre{
      background:rgba(2,6,23,.45);border:1px solid rgba(148,163,184,.18);
      border-radius:14px;padding:12px;margin:10px 0 0;overflow:auto;max-height:260px;
      white-space:pre-wrap;word-break:break-word;font-size:12px
    }
    .main{
      position:relative;border-radius:var(--r);overflow:hidden;border:1px solid var(--line);
      box-shadow:var(--shadow);background:rgba(2,6,23,.25)
    }
    #map{position:absolute;inset:0}
    .topbar{
      position:absolute;left:18px;right:18px;top:14px;display:flex;gap:10px;align-items:center;
      padding:10px;border-radius:999px;background:rgba(2,6,23,.45);
      border:1px solid rgba(148,163,184,.18);backdrop-filter:blur(10px)
    }
    .pill{
      display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:999px;
      border:1px solid rgba(148,163,184,.16);background:rgba(15,23,42,.35);min-width:240px
    }
    .pill input{border:none;background:transparent;padding:0;width:100%}
    .small{min-width:90px;width:90px;text-align:center}
    .hint{font-size:12px;color:var(--muted);margin-top:6px}
  </style>
</head>
<body>
  <div class="app">
    <div class="sidebar">

      <div class="card">
        <div class="title">AGOL Secure Proxy — Admin (OpenLayers)</div>
        <div class="tabs">
          <button class="tabbtn active" onclick="showTab('tab-register', this)">Register Alias</button>
          <button class="tabbtn" onclick="showTab('tab-client', this)">Create Client Key</button>
          <button class="tabbtn" onclick="showTab('tab-test', this)">Test Overlay + Identify</button>
        </div>

        <label>Proxy Base URL</label>
        <input id="proxyBase" placeholder="https://your-proxy.onrender.com" value=""/>

        <label>Admin Key</label>
        <input id="adminKey" type="password" placeholder="ADMIN_KEY"/>

        <div class="row" style="margin-top:12px">
          <button class="btn good" onclick="testAdmin()">Test Admin Access</button>
          <button class="btn" onclick="listServices()">List Services</button>
          <button class="btn" onclick="listClients()">List Clients</button>
        </div>

        <pre id="adminOut">{}</pre>
      </div>

      <div class="card section active" id="tab-register">
        <div class="title">1) Register Service Alias</div>
        <div class="hint">Admin-only. Adds FeatureServer query + VectorTileServer base.</div>

        <label>Alias</label>
        <input id="alias" value="ea_frame"/>

        <label>Feature layer Query URL (ends with /query)</label>
        <input id="flQueryUrl" placeholder="https://.../FeatureServer/0/query"/>

        <label>Vector Tile Server Base (ends with /VectorTileServer)</label>
        <input id="vtBase" placeholder="https://.../VectorTileServer"/>

        <label>Allowed Out Fields (comma-separated)</label>
        <textarea id="allowedFields" placeholder="OBJECTID,NAT_EA_SN,STATE_NAME,..."></textarea>

        <div class="row" style="margin-top:12px">
          <button class="btn primary full" onclick="registerAlias()">Register Alias</button>
        </div>

        <pre id="regOut">{}</pre>
      </div>

      <div class="card section" id="tab-client">
        <div class="title">2) Create Client Key</div>

        <label>Client Name</label>
        <input id="clientName" placeholder="Client A"/>

        <label>Allowed Services (comma-separated). Empty = all</label>
        <input id="clientServices" placeholder="ea_frame,buildings"/>

        <div class="row" style="margin-top:12px">
          <button class="btn primary full" onclick="createClient()">Create Client Key</button>
        </div>

        <pre id="clientOut">{}</pre>
      </div>

      <div class="card section" id="tab-test">
        <div class="title">3) Test Overlay + Identify</div>
        <div class="hint">
          OpenLayers loads your proxy tiles: <code>/tiles/{alias}/tile/{z}/{y}/{x}.pbf?key=...</code><br/>
          Click map to call <code>/v1/{alias}/identify</code>.
        </div>

        <label>Service Alias</label>
        <input id="testAlias" value="ea_frame"/>

        <label>Client Key</label>
        <input id="clientKey" placeholder="CK_..."/>

        <div class="row" style="margin-top:12px">
          <button class="btn good" onclick="loadOverlay()">Load Overlay</button>
          <button class="btn" onclick="clearOverlay()">Clear Overlay</button>
        </div>

        <pre id="identifyOut">{}</pre>
      </div>

    </div>

    <div class="main">
      <div id="map"></div>

      <div class="topbar">
        <div style="font-weight:700;opacity:.9;padding:0 8px">Map</div>
        <div class="pill">
          <input id="flyTo" value="8.67,9.08" title="lon,lat"/>
        </div>
        <div class="pill small">
          <input id="flyZoom" class="small" value="6" title="zoom"/>
        </div>
        <button class="btn" style="min-width:120px" onclick="fly()">Fly</button>
      </div>
    </div>
  </div>

<script>
  function showTab(id, el){
    document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
    document.getElementById(id).classList.add("active");
    document.querySelectorAll(".tabbtn").forEach(b => b.classList.remove("active"));
    el.classList.add("active");
  }

  function base(){
    const b = (document.getElementById("proxyBase").value || "").trim().replace(/\/+$/,"");
    return b || window.location.origin;
  }
  function adminKey(){ return (document.getElementById("adminKey").value || "").trim(); }

  async function fetchJson(url, opts={}){
    const r = await fetch(url, opts);
    const ct = r.headers.get("content-type") || "";
    const txt = await r.text();
    let data = null;
    try { data = ct.includes("application/json") ? JSON.parse(txt) : txt; } catch(e){ data = txt; }
    return { ok: r.ok, status: r.status, data };
  }

  async function testAdmin(){
    const url = `${base()}/admin/services?admin_key=${encodeURIComponent(adminKey())}`;
    const res = await fetchJson(url);
    document.getElementById("adminOut").textContent = JSON.stringify(res.data, null, 2);
  }
  async function listServices(){ return testAdmin(); }
  async function listClients(){
    const url = `${base()}/admin/clients?admin_key=${encodeURIComponent(adminKey())}`;
    const res = await fetchJson(url);
    document.getElementById("adminOut").textContent = JSON.stringify(res.data, null, 2);
  }

  async function registerAlias(){
    const params = new URLSearchParams({
      admin_key: adminKey(),
      alias: document.getElementById("alias").value.trim(),
      feature_layer_query_url: document.getElementById("flQueryUrl").value.trim(),
      vector_tile_base: document.getElementById("vtBase").value.trim(),
      allowed_out_fields: document.getElementById("allowedFields").value.trim()
    });
    const url = `${base()}/admin/register_service?${params.toString()}`;
    const res = await fetchJson(url, { method: "POST" });
    document.getElementById("regOut").textContent = JSON.stringify(res.data, null, 2);
  }

  async function createClient(){
    const params = new URLSearchParams({
      admin_key: adminKey(),
      name: document.getElementById("clientName").value.trim(),
      services: document.getElementById("clientServices").value.trim(),
      disabled: "false"
    });
    const url = `${base()}/admin/create_client?${params.toString()}`;
    const res = await fetchJson(url, { method: "POST" });
    document.getElementById("clientOut").textContent = JSON.stringify(res.data, null, 2);
    if(res.data && res.data.client_key){
      document.getElementById("clientKey").value = res.data.client_key;
    }
  }

  // ---------- OpenLayers Map ----------
  const olProj = ol.proj;
  const map = new ol.Map({
    target: 'map',
    layers: [
      new ol.layer.Tile({ source: new ol.source.OSM() })
    ],
    view: new ol.View({
      center: olProj.fromLonLat([8.67, 9.08]),
      zoom: 6
    })
  });

  let vtLayer = null;

  function fly(){
    const txt = document.getElementById("flyTo").value.trim();
    const z = parseFloat(document.getElementById("flyZoom").value || "6");
    const parts = txt.split(",").map(s => parseFloat(s.trim()));
    if(parts.length !== 2 || parts.some(n => Number.isNaN(n))) return;
    map.getView().animate({ center: olProj.fromLonLat([parts[0], parts[1]]), zoom: z, duration: 600 });
  }

  // Simple default style for all vector tile features
  const defaultStyle = new ol.style.Style({
    stroke: new ol.style.Stroke({ width: 1.5 }),
    fill: new ol.style.Fill({ color: 'rgba(255,255,255,0.08)' })
  });

  async function loadOverlay(){
    const alias = document.getElementById("testAlias").value.trim();
    const key = document.getElementById("clientKey").value.trim();
    if(!alias || !key){
      document.getElementById("identifyOut").textContent = "Set Service Alias and Client Key first.";
      return;
    }

    // IMPORTANT: OpenLayers XYZ uses {z}/{x}/{y} by default.
    // Your endpoint is /tile/{z}/{y}/{x}.pbf, so we must swap x/y in the template.
    const url = `${base()}/tiles/${encodeURIComponent(alias)}/tile/{z}/{y}/{x}.pbf?key=${encodeURIComponent(key)}`;

    if(vtLayer){
      map.removeLayer(vtLayer);
      vtLayer = null;
    }

    vtLayer = new ol.layer.VectorTile({
      source: new ol.source.VectorTile({
        format: new ol.format.MVT(),
        url: url
      }),
      style: defaultStyle
    });

    map.addLayer(vtLayer);

    document.getElementById("identifyOut").textContent =
      JSON.stringify({ ok:true, message:"Overlay loaded (OpenLayers MVT)", tileUrlTemplate:url }, null, 2);
  }

  function clearOverlay(){
    if(vtLayer){
      map.removeLayer(vtLayer);
      vtLayer = null;
    }
    document.getElementById("identifyOut").textContent = "{}";
  }

  // Identify on click (calls your FastAPI /v1/{alias}/identify)
  map.on('singleclick', async (evt) => {
    const alias = document.getElementById("testAlias").value.trim();
    const key = document.getElementById("clientKey").value.trim();
    if(!vtLayer || !alias || !key) return;

    const [lon, lat] = olProj.toLonLat(evt.coordinate);

    const url = `${base()}/v1/${encodeURIComponent(alias)}/identify?lat=${encodeURIComponent(lat)}&lon=${encodeURIComponent(lon)}&max_results=5&key=${encodeURIComponent(key)}`;
    const res = await fetchJson(url);

    document.getElementById("identifyOut").textContent =
      JSON.stringify({ click:{lat, lon}, http: res.status, data: res.data }, null, 2);
  });
</script>
</body>
</html>
"""




# -----------------------------
# Admin endpoints (dynamic registry)
# -----------------------------
@app.get("/admin/services")
def admin_list_services(
    x_admin_key: Optional[str] = Header(default=None),
    admin_key: Optional[str] = Query(default=None),
):
    require_admin(x_admin_key, admin_key)
    cfg = load_services()
    return {"services": cfg.get("services", {})}


@app.post("/admin/register_service")
def admin_register_service(
    alias: str = Query(...),
    feature_layer_query_url: str = Query(...),
    vector_tile_base: str = Query(...),
    allowed_out_fields: str = Query(..., description="Comma-separated list of fields"),
    x_admin_key: Optional[str] = Header(default=None),
    admin_key: Optional[str] = Query(default=None),
):
    require_admin(x_admin_key, admin_key)
    cfg = load_services()
    cfg.setdefault("services", {})

    fields = [f.strip() for f in allowed_out_fields.split(",") if f.strip()]
    if not fields:
        raise HTTPException(400, "allowed_out_fields cannot be empty")
    if not feature_layer_query_url.rstrip("/").endswith("/query"):
        raise HTTPException(400, "feature_layer_query_url must end with /query")

    cfg["services"][alias] = {
        "feature_layer_query_url": feature_layer_query_url,
        "vector_tile_base": vector_tile_base,
        "allowed_out_fields": fields,
    }
    write_json_atomic(SERVICES_CONFIG, cfg)
    return {"ok": True, "alias": alias, "fields_count": len(fields)}


@app.get("/admin/clients")
def admin_list_clients(
    x_admin_key: Optional[str] = Header(default=None),
    admin_key: Optional[str] = Query(default=None),
):
    require_admin(x_admin_key, admin_key)
    cfg = load_clients()
    return {"clients": cfg.get("clients", {})}


@app.post("/admin/create_client")
def admin_create_client(
    name: str = Query(...),
    services: str = Query("", description="Comma-separated aliases allowed for this key. Empty means all."),
    disabled: bool = Query(False),
    x_admin_key: Optional[str] = Header(default=None),
    admin_key: Optional[str] = Query(default=None),
):
    require_admin(x_admin_key, admin_key)
    cfg = load_clients()
    cfg.setdefault("clients", {})

    new_key = "CK_" + secrets.token_urlsafe(24)
    svc_list = [s.strip() for s in services.split(",") if s.strip()]

    cfg["clients"][new_key] = {
        "name": name,
        "services": svc_list,
        "disabled": bool(disabled),
        "where_lock": {},
    }
    write_json_atomic(CLIENTS_CONFIG, cfg)
    return {"ok": True, "client_key": new_key, "name": name, "services": svc_list}


@app.post("/admin/disable_client")
def admin_disable_client(
    client_key: str = Query(...),
    disabled: bool = Query(True),
    x_admin_key: Optional[str] = Header(default=None),
    admin_key: Optional[str] = Query(default=None),
):
    require_admin(x_admin_key, admin_key)
    cfg = load_clients()
    rec = cfg.get("clients", {}).get(client_key)
    if not rec:
        raise HTTPException(404, "Unknown client key")
    rec["disabled"] = bool(disabled)
    write_json_atomic(CLIENTS_CONFIG, cfg)
    return {"ok": True, "client_key": client_key, "disabled": bool(disabled)}


@app.get("/v1/services")
def list_services(x_api_key: Optional[str] = Header(default=None), key: Optional[str] = Query(default=None)):
    client_key = (x_api_key or key or "").strip()
    if not client_key:
        raise HTTPException(401, "Unauthorized: missing key")
    client_rec = get_client_record(client_key)

    cfg = load_services()
    all_aliases = list(cfg.get("services", {}).keys())

    allowed = client_rec.get("services", [])
    if allowed:
        aliases = [a for a in all_aliases if a in allowed]
    else:
        aliases = all_aliases

    return {"services": aliases}


# -----------------------------
# Attributes-only endpoints
# -----------------------------
@app.get("/v1/{alias}/query")
async def query_attributes_only(
    alias: str,
    where: str = Query("1=1"),
    outFields: Optional[str] = Query(None),
    orderByFields: Optional[str] = Query(None),
    resultOffset: int = Query(0, ge=0),
    resultRecordCount: int = Query(200, ge=1, le=2000),
    returnDistinctValues: bool = Query(False),
    x_api_key: Optional[str] = Header(default=None),
    key: Optional[str] = Query(default=None),
):
    client_rec = enforce_access(alias=alias, x_api_key=x_api_key, key=key)
    cfg = load_services()
    svc = cfg.get("services", {}).get(alias)
    if not svc:
        raise HTTPException(404, "Unknown service alias")

    allowed = svc.get("allowed_out_fields", [])
    if not allowed:
        raise HTTPException(500, "allowed_out_fields missing for service")

    qurl = svc["feature_layer_query_url"]
    token = await get_agol_token(cfg)

    where_final = apply_where_lock(client_rec, alias, where)

    params = {
        "f": "json",
        "where": where_final,
        "outFields": sanitize_outfields(outFields, allowed),
        "returnGeometry": "false",
        "resultOffset": str(resultOffset),
        "resultRecordCount": str(resultRecordCount),
        "returnDistinctValues": "true" if returnDistinctValues else "false",
        "token": token,
    }
    if orderByFields:
        params["orderByFields"] = orderByFields

    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(qurl, params=params)
        j = r.json()

    if "error" in j:
        return JSONResponse(status_code=400, content=j)

    feats = j.get("features", [])
    for f in feats:
        f.pop("geometry", None)
    j["features"] = feats
    return j


@app.get("/v1/{alias}/identify")
async def identify_attributes_only(
    alias: str,
    lat: float,
    lon: float,
    max_results: int = Query(5, ge=1, le=20),
    x_api_key: Optional[str] = Header(default=None),
    key: Optional[str] = Query(default=None),
):
    client_rec = enforce_access(alias=alias, x_api_key=x_api_key, key=key)
    cfg = load_services()
    svc = cfg.get("services", {}).get(alias)
    if not svc:
        raise HTTPException(404, "Unknown service alias")

    allowed: List[str] = svc.get("allowed_out_fields", [])
    if not allowed:
        raise HTTPException(500, "allowed_out_fields missing for service")

    qurl = svc["feature_layer_query_url"]
    token = await get_agol_token(cfg)

    where_final = apply_where_lock(client_rec, alias, "1=1")

    # ✅ AGOL likes geometry as Esri JSON
    geometry_json = json.dumps({
        "x": lon,
        "y": lat,
        "spatialReference": {"wkid": 4326}
    })

    params = {
        "f": "json",
        "where": where_final,
        "geometry": geometry_json,
        "geometryType": "esriGeometryPoint",
        "inSR": "4326",
        "spatialRel": "esriSpatialRelIntersects",
        "outFields": ",".join(allowed),      # ✅ request only allowed fields
        "returnGeometry": "false",
        "resultRecordCount": str(max_results),
        "outSR": "4326",
        "token": token,
    }

    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(qurl, params=params)
        j = r.json()

    if "error" in j:
        return JSONResponse(status_code=400, content=j)

    feats = j.get("features", [])
    cleaned = []
    for f in feats:
        attrs = (f.get("attributes") or {})
        safe_attrs = {k: attrs.get(k) for k in allowed if k in attrs}
        cleaned.append({"attributes": safe_attrs})

    return {"count": len(cleaned), "results": cleaned}


# -----------------------------
# Vector Tile proxy endpoints
# -----------------------------
@app.get("/tiles/{alias}/style.json")
async def vt_style(
    alias: str,
    x_api_key: Optional[str] = Header(default=None),
    key: Optional[str] = Query(default=None),
):
    enforce_access(alias=alias, x_api_key=x_api_key, key=key)
    require_public_base()

    cfg = load_services()
    svc = cfg.get("services", {}).get(alias)
    if not svc:
        raise HTTPException(404, "Unknown service alias")

    base = svc.get("vector_tile_base")
    if not base:
        raise HTTPException(500, "vector_tile_base missing for service")

    token = await get_agol_token(cfg)
    style_url = f"{base.rstrip('/')}/resources/styles/root.json"

    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(style_url, params={"f": "json", "token": token})
        style = r.json()

    key_q = (key or x_api_key or "").strip()

    for src in style.get("sources", {}).values():
        if "url" in src:
            src.pop("url", None)

        if src.get("type") == "vector":
            src["tiles"] = [
                f"{PUBLIC_PROXY_BASE}/tiles/{alias}/tile/{{z}}/{{y}}/{{x}}.pbf?key={key_q}"
            ]
            src.setdefault("scheme", "xyz")
            src.setdefault("minzoom", 0)
            src.setdefault("maxzoom", 23)

    if "sprite" in style:
        style["sprite"] = f"{PUBLIC_PROXY_BASE}/tiles/{alias}/sprite/{key_q}"

    if "glyphs" in style:
        style["glyphs"] = f"{PUBLIC_PROXY_BASE}/tiles/{alias}/fonts/{{fontstack}}/{{range}}.pbf?key={key_q}"

    return style


@app.get("/tiles/{alias}/tile/{z}/{y}/{x}.pbf")
async def vt_tile(
    alias: str,
    z: int,
    y: int,
    x: int,
    x_api_key: Optional[str] = Header(default=None),
    key: Optional[str] = Query(default=None),
):
    enforce_access(alias=alias, x_api_key=x_api_key, key=key)

    cfg = load_services()
    svc = cfg.get("services", {}).get(alias)
    if not svc:
        raise HTTPException(404, "Unknown service alias")

    base = svc.get("vector_tile_base")
    if not base:
        raise HTTPException(500, "vector_tile_base missing for service")

    token = await get_agol_token(cfg)
    tile_url = f"{base.rstrip('/')}/tile/{z}/{y}/{x}.pbf"

    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(tile_url, params={"token": token})
        if r.status_code == 404:
            return Response(status_code=404)
        r.raise_for_status()
        return Response(content=r.content, media_type="application/x-protobuf")


# ---- Sprites (key is in PATH, because sprite url cannot use querystring reliably) ----
@app.get("/tiles/{alias}/sprite/{client_key}.json")
async def vt_sprite_json(alias: str, client_key: str):
    enforce_access(alias=alias, x_api_key=None, key=client_key)
    cfg = load_services()
    svc = cfg.get("services", {}).get(alias)
    if not svc:
        raise HTTPException(404, "Unknown service alias")
    base = svc.get("vector_tile_base")
    if not base:
        raise HTTPException(500, "vector_tile_base missing for service")

    token = await get_agol_token(cfg)
    url = f"{base.rstrip('/')}/resources/sprites/sprite.json"
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(url, params={"token": token})
        r.raise_for_status()
        return JSONResponse(content=r.json())


@app.get("/tiles/{alias}/sprite/{client_key}.png")
async def vt_sprite_png(alias: str, client_key: str):
    enforce_access(alias=alias, x_api_key=None, key=client_key)
    cfg = load_services()
    svc = cfg.get("services", {}).get(alias)
    if not svc:
        raise HTTPException(404, "Unknown service alias")
    base = svc.get("vector_tile_base")
    if not base:
        raise HTTPException(500, "vector_tile_base missing for service")

    token = await get_agol_token(cfg)
    url = f"{base.rstrip('/')}/resources/sprites/sprite.png"
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(url, params={"token": token})
        r.raise_for_status()
        return Response(content=r.content, media_type="image/png")


@app.get("/tiles/{alias}/sprite/{client_key}@2x.json")
async def vt_sprite2x_json(alias: str, client_key: str):
    enforce_access(alias=alias, x_api_key=None, key=client_key)
    cfg = load_services()
    svc = cfg.get("services", {}).get(alias)
    if not svc:
        raise HTTPException(404, "Unknown service alias")
    base = svc.get("vector_tile_base")
    if not base:
        raise HTTPException(500, "vector_tile_base missing for service")

    token = await get_agol_token(cfg)
    url = f"{base.rstrip('/')}/resources/sprites/sprite@2x.json"
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(url, params={"token": token})
        if r.status_code == 404:
            return Response(status_code=404)
        r.raise_for_status()
        return JSONResponse(content=r.json())


@app.get("/tiles/{alias}/sprite/{client_key}@2x.png")
async def vt_sprite2x_png(alias: str, client_key: str):
    enforce_access(alias=alias, x_api_key=None, key=client_key)
    cfg = load_services()
    svc = cfg.get("services", {}).get(alias)
    if not svc:
        raise HTTPException(404, "Unknown service alias")
    base = svc.get("vector_tile_base")
    if not base:
        raise HTTPException(500, "vector_tile_base missing for service")

    token = await get_agol_token(cfg)
    url = f"{base.rstrip('/')}/resources/sprites/sprite@2x.png"
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(url, params={"token": token})
        if r.status_code == 404:
            return Response(status_code=404)
        r.raise_for_status()
        return Response(content=r.content, media_type="image/png")


@app.get("/tiles/{alias}/fonts/{fontstack}/{range}.pbf")
async def vt_fonts(
    alias: str,
    fontstack: str,
    range: str,
    x_api_key: Optional[str] = Header(default=None),
    key: Optional[str] = Query(default=None),
):
    enforce_access(alias=alias, x_api_key=x_api_key, key=key)
    cfg = load_services()
    svc = cfg.get("services", {}).get(alias)
    if not svc:
        raise HTTPException(404, "Unknown service alias")

    base = svc.get("vector_tile_base")
    if not base:
        raise HTTPException(500, "vector_tile_base missing for service")

    token = await get_agol_token(cfg)
    fonts_url = f"{base.rstrip('/')}/resources/fonts/{fontstack}/{range}.pbf"

    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(fonts_url, params={"token": token})
        if r.status_code == 404:
            return Response(status_code=404)
        r.raise_for_status()
        return Response(content=r.content, media_type="application/x-protobuf")
