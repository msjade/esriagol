# Client Guide — Secure Overlay + Attribute Query

You will receive:
- A **CLIENT KEY**
- One or more **dataset aliases** (examples: `ipa_ea_frame_v1`, `ipa_bld_sample_v1`)
- The proxy base URL (example: `https://proxy.yourdomain.com`)

---

## 1) Overlay (Vector Tiles)

### Style URL (Mapbox GL / MapLibre GL / ArcGIS JS style loading)
```
https://proxy.yourdomain.com/tiles/<ALIAS>/style.json?key=<CLIENTKEY>
```

### Raw XYZ tile URL (OpenLayers and other setups)
```
https://proxy.yourdomain.com/tiles/<ALIAS>/tile/{z}/{y}/{x}.pbf?key=<CLIENTKEY>
```

---

## 2) Click / Identify (attributes only — no geometry)
```
https://proxy.yourdomain.com/v1/<ALIAS>/identify?lat=<LAT>&lon=<LON>&key=<CLIENTKEY>
```

Response:
```json
{
  "count": 1,
  "results": [
    { "attributes": { "...": "..." } }
  ]
}
```

---

## 3) Attribute Table Query (attributes only — no geometry)
Example:
```
https://proxy.yourdomain.com/v1/<ALIAS>/query?where=STATE_NAME%3D%27Kwara%27&key=<CLIENTKEY>
```

Optional:
- `outFields=FIELD1,FIELD2`
- `resultOffset=0`
- `resultRecordCount=200`
- `orderByFields=FIELD1 ASC`

Note: the server ignores fields you are not permitted to see.
