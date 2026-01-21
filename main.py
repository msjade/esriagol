import os, json, time, pathlib, secrets
from typing import Dict, Any, Optional, List

import httpx
from fastapi import FastAPI, HTTPException, Query, Header, Response
from fastapi.responses import JSONResponse

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
        "expiration": "60"
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


@app.get("/health")
def health():
    return {"ok": True, "service": APP_TITLE}


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
        "allowed_out_fields": fields
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
        "where_lock": {}
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
    # List only what this key is allowed to see
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
        "token": token
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

    allowed = svc.get("allowed_out_fields", [])
    qurl = svc["feature_layer_query_url"]
    token = await get_agol_token(cfg)

    where_final = apply_where_lock(client_rec, alias, "1=1")

    params = {
        "f": "json",
        "where": where_final,
        "geometry": f"{lon},{lat}",
        "geometryType": "esriGeometryPoint",
        "inSR": "4326",
        "spatialRel": "esriSpatialRelIntersects",
        "outFields": ",".join(allowed),
        "returnGeometry": "false",
        "resultRecordCount": str(max_results),
        "token": token
    }

    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(qurl, params=params)
        j = r.json()

    if "error" in j:
        return JSONResponse(status_code=400, content=j)

    feats = j.get("features", [])
    for f in feats:
        f.pop("geometry", None)

    return {"count": len(feats), "results": feats}


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

    # Rewrite tiles so every resource continues to pass key=...
    key_q = key or ""
    for src in style.get("sources", {}).values():
        tiles = src.get("tiles")
        if isinstance(tiles, list) and tiles:
            src["tiles"] = [f"{PUBLIC_PROXY_BASE}/tiles/{alias}/tile/{{z}}/{{y}}/{{x}}.pbf?key={key_q}"]

    if "sprite" in style:
        style["sprite"] = f"{PUBLIC_PROXY_BASE}/tiles/{alias}/sprite?key={key_q}"
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


@app.get("/tiles/{alias}/sprite.json")
async def vt_sprite_json(
    alias: str,
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
    url = f"{base.rstrip('/')}/resources/sprites/sprite.json"
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(url, params={"token": token})
        r.raise_for_status()
        return JSONResponse(content=r.json())


@app.get("/tiles/{alias}/sprite.png")
async def vt_sprite_png(
    alias: str,
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
    url = f"{base.rstrip('/')}/resources/sprites/sprite.png"
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(url, params={"token": token})
        r.raise_for_status()
        return Response(content=r.content, media_type="image/png")


@app.get("/tiles/{alias}/sprite@2x.json")
async def vt_sprite2x_json(
    alias: str,
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
    url = f"{base.rstrip('/')}/resources/sprites/sprite@2x.json"
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(url, params={"token": token})
        if r.status_code == 404:
            return Response(status_code=404)
        r.raise_for_status()
        return JSONResponse(content=r.json())


@app.get("/tiles/{alias}/sprite@2x.png")
async def vt_sprite2x_png(
    alias: str,
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
