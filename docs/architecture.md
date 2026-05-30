# Architecture

The project is a **single Cloudflare Worker module** (`multiclouds3 v7.0.js`) that fronts
four S3-compatible providers and adds an AI agent + MCP server. It depends only on
Web-standard APIs (`fetch`, Web Crypto, Cache API) — no npm packages, so it can be deployed
by pasting into the dashboard or via Wrangler.

```
                         ┌─────────────────────────────────────────────┐
   Browser / WebDAV ───► │  Cloudflare Worker (fetch handler)           │
   MCP client ─────────► │                                              │
   AI chat (UI) ───────► │  1 OPTIONS → CORS                            │
                         │  2 /favicon.ico                              │
                         │  3 /mcp → JSON-RPC (bearer/basic)            │
                         │  4 Basic-auth gate (fail-closed)             │
                         │  5 ?search / ?bulkExport / ?bulkDelete       │
                         │  6 ?aiChat (POST) → agent loop ──► OpenRouter │
                         │  7 provider routing:                         │
                         │     ?share ?download ?stream ?preview        │
                         │     browse / DELETE                          │
                         └───────────┬──────────────────────┬──────────┘
                                     │ AWS SigV4            │ Cache API
                                     ▼                      ▼
                    ┌──────────────────────────┐   ┌──────────────────┐
                    │ Impossible / Wasabi / R2 │   │ caches.default   │
                    │ / OCI  (S3 API)          │   │ (CDN edge cache) │
                    └──────────────────────────┘   └──────────────────┘
```

## Request lifecycle

1. **`fetch(request, env, ctx)`** is the single entry point.
2. `OPTIONS`, favicon, and `/mcp` are handled before auth.
3. `checkAuth` validates HTTP Basic credentials with a **constant-time** compare and
   **fails closed** if no password is configured.
4. Utility routes (`search`, `bulkExport`, `bulkDelete`, `aiChat`) are matched on query flags.
5. `determineProviderAndCleanPath` maps the URL prefix to a provider and clean key.
6. `getProviderConfig` assembles credentials/endpoint from `env` (throws if incomplete).
7. The selected handler signs an S3 request and streams/serves the result.

## Request signing (AWS SigV4)

`signRequest()` builds a canonical request, signs it with `getSignatureKey` / `hmacSha256`,
and returns `{ url, headers }`. It supports:
- **virtual-hosted** style (`bucket.endpoint`) for Impossible/Wasabi/R2 and **path** style
  (`endpoint/bucket`) for OCI;
- a `Range` header passthrough;
- arbitrary **extra signed headers** (e.g. `x-amz-copy-source` for server-side copy);
- `UNSIGNED-PAYLOAD` for body uploads.

`generatePresignedUrl()` produces query-signed URLs for share/direct links.

## Listing & pagination

`listObjects()` calls `ListObjectsV2` with `encoding-type=url`, follows
`NextContinuationToken` (capped at 20 pages ≈ 20k objects per listing), de-dupes folders,
and returns `{ folders, files, truncated }`. `parseListBucketResult()` decodes percent-encoded
keys/prefixes (preserving literal `+`) and captures `ETag`. The continuation token is **not**
URL-decoded (it isn't encoded by S3).

## Caching

`?download`, `?stream`, and `?preview` use `caches.default`:
- Cache key = request URL minus the flag.
- Only **full `200`** responses **≤ 256 MB** and **without** a `Range` header are stored
  (prevents range-cache poisoning).
- TTL: 2 h for small files, 30 min for files > 100 MB (`stale-while-revalidate`).
- Search result pages are cached for `searchCacheTime` seconds via a synthetic cache key.

## AI agent loop (`handleAIChat`)

1. Build a system prompt describing the tools.
2. Loop up to `maxIterations`:
   - Call OpenRouter with `tools` (native function-calling). If the model/provider rejects
     `tools` (4xx), disable it and retry via the **text protocol** (`TOOL_CALL:` parsing).
   - Execute any requested tool via `executeAgentTool`, append results (trimmed), continue.
   - When the model replies without a tool call, return that as the final message.
3. Upstream calls use `fetchWithRetry` (timeout + exponential backoff).

## MCP server (`handleMcp`)

A stateless JSON-RPC 2.0 handler reusing `AGENT_TOOLS` + `toJsonSchema`. See [mcp.md](./mcp.md).

## Security model

- Credentials from secrets; constant-time compare; fail-closed.
- All user-controlled strings escaped before HTML (`escapeHtml`, `jsAttr`).
- Errors hide internals unless `CONFIG.debug`.
- CORS does not pre-authorize cross-origin `DELETE`; `/mcp` preflight allows `POST`.

## Key functions (map)

| Area | Functions |
|------|-----------|
| Entry/routing | `fetch`, `determineProviderAndCleanPath`, `getProviderConfig` |
| Auth/CORS/util | `checkAuth`, `timingSafeEqual`, `handleOptions`, `addCorsHeaders`, `escapeHtml`, `jsAttr`, `fetchWithRetry`, `trimForModel`, `contentDisposition` |
| Signing/crypto | `signRequest`, `generatePresignedUrl`, `sha256`, `hmacSha256`, `getSignatureKey` |
| S3 | `listObjects`, `parseListBucketResult`, `decodeS3Value`, `s3CopyObject`, `s3UploadBody` |
| Handlers | `handleBrowse`, `handleDownload`, `handleStream`, `handlePreview`, `handleVideoPreview`, `handleShareLink`, `handleDelete`, `handleGlobalSearch`, `handleBulkExport`, `handleBulkDelete`, `handleAIChat`, `handleMcp` |
| Agent | `AGENT_TOOLS`, `executeAgentTool`, `agent*` tools, `buildAgenticSystemPrompt`, `parseToolRequest`, `agentToolsForOpenAI`, `toJsonSchema` |
| UI | `getBrowsePage`, `getLoginPage`, `getErrorPage`, `getSearchResultsPage` |
