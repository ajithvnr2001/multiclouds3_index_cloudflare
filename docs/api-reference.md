# HTTP API Reference

This document describes every HTTP endpoint of the Multi-Cloud S3 Index Worker (v7.0).
For a machine-readable contract, see [`openapi.yaml`](./openapi.yaml).

> All endpoints (except `OPTIONS` and `/favicon.ico`) require **HTTP Basic** authentication
> when `passwordProtected` is enabled. Credentials come from the `AUTH_USERNAME` /
> `AUTH_PASSWORD` secrets. See [configuration.md](./configuration.md).

---

## 1. Routing model

The Worker inspects the request **in this order**:

1. `OPTIONS` → CORS preflight (`handleOptions`).
2. `/favicon.ico` → favicon.
3. `/mcp` → [MCP server](./mcp.md) (its own auth).
4. **Auth gate** — Basic auth required for everything below.
5. `?search=` → global search.
6. `?bulkExport=` → bulk link export.
7. `?bulkDelete` → bulk delete.
8. `?aiChat` (POST) → AI agent.
9. Provider routing → `?share` / `?download` / `?preview` / `?stream` / browse / `DELETE`.

### Provider prefixes

| URL prefix     | Provider id       | Addressing  |
|----------------|-------------------|-------------|
| `/impossible/` | `impossiblecloud` | virtual     |
| `/wasabi/`     | `wasabi`          | virtual     |
| `/r2/`         | `cloudflarer2`    | virtual     |
| `/oci/`        | `oraclecloud`     | **path**    |
| _(no prefix)_  | default (`impossiblecloud`) | — |

Everything after the prefix is the S3 **object key** (may contain `/`). The matched
prefix is preserved in keys returned by listings (e.g. `wasabi/videos/a.mp4`) so the
HTML UI can build links; server-side S3 calls strip it.

---

## 2. Browse

```
GET /                      → default provider root (HTML)
GET /wasabi/               → Wasabi root (HTML)
GET /wasabi/videos/        → "videos" folder (HTML)
```

Returns a responsive HTML page with folder/file cards, sorting, theme switching,
bulk-select, and the AI chat panel. Listings use S3 `ListObjectsV2` with
`delimiter=/` and follow `NextContinuationToken` (no 1000-object cap).

---

## 3. File operations

All of these target `GET /{provider}/{key}` and are selected by a query flag.

### 3.1 Download — `?download`
Forces a browser download.

```bash
curl -u user:pass -L "https://$HOST/wasabi/videos/movie.mp4?download" -o movie.mp4
```
- `Content-Disposition: attachment; filename="..."; filename*=UTF-8''...`
- Supports `Range` (returns `206`).
- Full `200` responses ≤ 256 MB are cached (`CF-Cache-Status: MISS|HIT`); range requests `BYPASS`.

### 3.2 Stream — `?stream`
Inline, CDN-cached delivery for media players (MX Player, VLC, Kodi). Same caching/range
behavior as download but `Content-Disposition: inline`. MKV is served as `video/webm`
when `experimentalMkvSupport` is on. HLS segments (`segment-N.ts/m4s`) trigger background
prefetch of the next segment.

### 3.3 Preview — `?preview`
- **Video** → returns an HTML player page (`handleVideoPreview`) with the stream URL.
- **Other previewable types** (images, audio, pdf) → inline bytes.

### 3.4 Share link — `?share`
Returns JSON. Add `&cdn=true` for a Worker/CDN URL; otherwise a direct S3 link.

```bash
# Direct S3 (presigned, 7 days) — OCI public buckets return a permanent public URL
curl -u user:pass "https://$HOST/wasabi/videos/movie.mp4?share"
# CDN (Worker) link
curl -u user:pass "https://$HOST/wasabi/videos/movie.mp4?share&cdn=true"
```

```jsonc
// direct
{ "success": true, "url": "https://bucket.s3...?X-Amz-...", "type": "direct",
  "expires_in_seconds": 604800, "note": "🔗 Direct S3 - Best compatibility" }
// cdn
{ "success": true, "url": "https://HOST/wasabi/videos/movie.mp4?stream", "type": "cdn",
  "expires_in_seconds": null, "note": "⚡ CDN-Accelerated - Fast for repeated viewing" }
```

### 3.5 Delete — `DELETE`
```bash
curl -u user:pass -X DELETE "https://$HOST/wasabi/videos/movie.mp4"
```
```json
{ "success": true, "message": "File deleted successfully" }
```
Requires `s3:DeleteObject`. Cross-origin `DELETE` is **not** pre-authorized by CORS.

---

## 4. Global search — `?search=`

```bash
curl -u user:pass "https://$HOST/?search=backup"
```
- Minimum 2 characters.
- Searches all configured providers in parallel (`Promise.allSettled`); a misconfigured
  provider is reported as an error, not fatal.
- Results are sorted (exact match first, then shorter names).
- Returns an HTML results page. Successful result sets are cached for `searchCacheTime`
  seconds (`X-Search-Cache: HIT|MISS`).

---

## 5. Bulk operations

The `files` parameter is a comma-separated list of `provider:path` entries, where `path`
includes the routing prefix:

```
files=wasabi:wasabi/videos/a.mp4,r2:r2/docs/b.pdf
```

### 5.1 Bulk export — `?bulkExport=<type>&files=<list>`
`type` ∈ `all | cdn | direct | download | json | markdown`.

```bash
curl -u user:pass "https://$HOST/?bulkExport=markdown&files=wasabi:wasabi/a.mp4,r2:r2/b.pdf"
```
- `json` → array of `{ fileName, path, provider, cdnUrl, directUrl, downloadUrl, success }`.
- `markdown` → `text/markdown`. Others → `text/plain`.

### 5.2 Bulk delete — `?bulkDelete&files=<list>`
```bash
curl -u user:pass "https://$HOST/?bulkDelete&files=wasabi:wasabi/a.mp4,r2:r2/b.pdf"
```
```json
{ "success": true, "total": 2, "deleted": 2, "failed": 0,
  "results": [ { "success": true, "fileName": "a.mp4", "provider": "Wasabi", "message": "Deleted successfully" } ] }
```

---

## 6. AI agent — `POST /?aiChat`

```bash
curl -u user:pass -X POST "https://$HOST/?aiChat" \
  -H "Content-Type: application/json" \
  -d '{"message":"find duplicates and tell me how much space I can save"}'
```
Request body: `{ message, context?, conversationHistory? }`.
Response: `{ success, message, model, agentic, iterations, toolCalls:[{tool, success}] }`.

The agent uses OpenRouter with native tool-calling (and a text-protocol fallback for models
that reject the `tools` parameter). See [agent-tools.md](./agent-tools.md) for the 11 tools.

---

## 7. MCP — `POST /mcp`

JSON-RPC 2.0 remote MCP server exposing the same 11 tools. See the dedicated
[mcp.md](./mcp.md) reference.

---

## 8. Common headers

| Header | Direction | Notes |
|--------|-----------|-------|
| `Authorization: Basic ...` | request | UI/API auth |
| `Authorization: Bearer ...` | request | `/mcp` only (`MCP_TOKEN`) |
| `Range: bytes=...` | request | partial content (`206`, cache bypass) |
| `CF-Cache-Status` | response | `HIT` / `MISS` / `BYPASS` |
| `X-Provider` | response | provider that served the object |
| `X-Response-Time` | response | origin fetch time (ms) |
| `Content-Range`, `Accept-Ranges` | response | range responses |
| `Access-Control-Allow-Origin` | response | from `CONFIG.corsAllowOrigin` |

---

## 9. Errors

- **Browse/preview/stream/download** errors render a friendly **HTML** error page.
  Technical details are hidden unless `CONFIG.debug` is `true`.
- **JSON** endpoints (share, bulk, delete, aiChat, mcp) return JSON errors.
- **401** responses include `WWW-Authenticate: Basic realm="<siteName>"`.
