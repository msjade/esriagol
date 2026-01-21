# Admin Guide — AGOL Secure Overlay + Attributes Proxy

## What this proxy does
You publish **sampled** datasets in ArcGIS Online as:
1) **Hosted Feature Layer** (FeatureServer) — kept private
2) **Vector Tile Layer** (VectorTileServer) — kept private

This proxy:
- Streams vector tiles to clients (overlay) without exposing your AGOL token.
- Supports click/identify and attribute table queries **without returning geometry** (attributes-only).
- Enforces access per client using a **client key**.
- Optionally enforces per-client area limits with a `where_lock`.

---

## Project files
- `main.py` — FastAPI application
- `services.json` — registry of dataset aliases (FS + VT) and allowed fields
- `clients.json` — registry of client keys and which aliases they can access
- `requirements.txt` — Python dependencies
- `Dockerfile` — container deployment (optional)

---

## 1) Add a new sampled dataset (manual)
Each sampled package needs:
- Feature layer query URL: `.../FeatureServer/<layerIndex>/query`
- Vector tile base URL: `.../VectorTileServer`
- An allowlist of attribute fields clients are permitted to see

### Example `services.json` entry
```json
"clientA_frame_v1": {
  "feature_layer_query_url": "https://services.arcgis.com/.../FeatureServer/0/query",
  "vector_tile_base": "https://vectortileservices.arcgis.com/.../VectorTileServer",
  "allowed_out_fields": ["STATE_NAME","LGA_NAME","WARD_NAME","EA_ID","NAT_EA_SN"]
}
```

---

## 2) Create client keys and grant access (manual)
Edit `clients.json`:

```json
{
  "clients": {
    "CLIENTKEY_ABC": {
      "name": "Client ABC",
      "services": ["clientA_frame_v1"],
      "disabled": false,
      "where_lock": {
        "clientA_frame_v1": "STATE_NAME = 'Kwara'"
      }
    }
  }
}
```

**services**: list of dataset aliases this key is allowed to access.  
**where_lock** *(optional)*: a SQL snippet that is AND-ed to every query/identify for that alias.

---

## 3) Environment variables (required)
### AGOL credentials (used only by the proxy)
- `AGOL_USERNAME`
- `AGOL_PASSWORD`

### Public proxy URL (used to rewrite style.json)
- `PUBLIC_PROXY_BASE`
  - Example: `https://proxy.yourdomain.com`

### Admin key (required if you use /admin endpoints)
- `ADMIN_KEY`

---

## 4) Run locally
```bash
pip install -r requirements.txt
export AGOL_USERNAME="..."
export AGOL_PASSWORD="..."
export PUBLIC_PROXY_BASE="http://localhost:8000"
export ADMIN_KEY="a-long-random-admin-key"
uvicorn main:app --host 0.0.0.0 --port 8000
```

Health check:
- `GET /health`

---

## 5) Run with Docker
```bash
docker build -t agol-secure-proxy .
docker run -p 8000:8000 \
  -e AGOL_USERNAME="..." \
  -e AGOL_PASSWORD="..." \
  -e PUBLIC_PROXY_BASE="https://proxy.yourdomain.com" \
  -e ADMIN_KEY="a-long-random-admin-key" \
  agol-secure-proxy
```

---

## 6) Admin endpoints (no JSON edits)
These endpoints let you register services and create/disable client keys without editing JSON files.

### List services
`GET /admin/services?admin_key=<ADMIN_KEY>`

### Register/update a service alias
`POST /admin/register_service?admin_key=<ADMIN_KEY>&alias=...&feature_layer_query_url=.../query&vector_tile_base=.../VectorTileServer&allowed_out_fields=FIELD1,FIELD2`

### List clients
`GET /admin/clients?admin_key=<ADMIN_KEY>`

### Create a client key
`POST /admin/create_client?admin_key=<ADMIN_KEY>&name=ClientA&services=ipa_ea_frame_v1,ipa_bld_sample_v1`

### Disable a client key
`POST /admin/disable_client?admin_key=<ADMIN_KEY>&client_key=<CLIENTKEY>&disabled=true`

Security note: protect admin endpoints (VPN / IP allowlist / reverse proxy auth). Never expose ADMIN_KEY publicly.
