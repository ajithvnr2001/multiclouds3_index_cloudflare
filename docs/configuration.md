# Configuration

Two layers of configuration:

1. **`CONFIG`** — an object at the top of `multiclouds3 v7.0.js` (behavior, theme, AI, routing).
2. **Environment / secrets** — credentials and API keys provided by the Worker runtime
   (`env`). Never hard-code these.

---

## 1. `CONFIG` options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `siteName` | string | `"Multi-Cloud S3 Index"` | Title / Basic-auth realm |
| `siteIcon` | string | `"🌤️"` | Emoji icon |
| `theme` | string | `"dark"` | One of `availableThemes` |
| `defaultPath` | string | `""` | Reserved |
| `passwordProtected` | boolean | `true` | Require Basic auth |
| `authMode` | string | `"username"` | `"username"` (user+pass) or `"password"` (pass only) |
| `username` | string | `""` | **Leave blank**; use `AUTH_USERNAME` secret |
| `password` | string | `""` | **Leave blank**; use `AUTH_PASSWORD` secret |
| `corsAllowOrigin` | string | `"*"` | `Access-Control-Allow-Origin` value |
| `debug` | boolean | `false` | Expose technical error details (never enable in prod) |
| `enableMCP` | boolean | `true` | Serve the MCP server at `/mcp` |
| `experimentalMkvSupport` | boolean | `true` | Serve `.mkv` as `video/webm` for inline playback |
| `routingStrategy` | string | `"path-based"` | Routing mode |
| `pathRouting` | object | see code | Prefix → provider id map (+ `default`) |
| `providerPriority` | string[] | 4 providers | Order used by cross-provider tools |
| `defaultSort` | object | `{field:"name",direction:"asc"}` | Initial UI sort |
| `enableAIChat` | boolean | `true` | Enable the AI assistant |
| `aiProvider` | string | `"openrouter"` | AI backend |
| `aiModel` | string | `"minimax/minimax-m2:free"` | OpenRouter model id |
| `enableAgenticAI` | boolean | `true` | Enable tool use |
| `agentConfig.maxIterations` | number | `8` | Max reasoning steps per request |
| `agentConfig.enableAutoExecution` | boolean | `true` | Allow write operations |
| `agentConfig.requireConfirmation` | boolean | `false` | Require `confirm:true` for destructive tools |
| `agentConfig.tools` | string[] | 11 tools | Enabled tool names |
| `availableThemes` | object | 6 themes | Theme palettes |
| `enableGlobalSearch` | boolean | `true` | Enable `?search=` |
| `searchCacheTime` | number | `300` | Search result cache TTL (seconds); `0` disables |

Optional (read if present): `CONFIG.publicBaseUrl` — fallback origin for generated links
when no request origin is available.

---

## 2. Environment variables & secrets

Set sensitive values as **secrets** (`wrangler secret put NAME`) or **encrypted** dashboard
variables. Plain (non-secret) vars like regions can be set as normal vars.

### Auth, AI, MCP
| Name | Required | Description |
|------|----------|-------------|
| `AUTH_USERNAME` | when `passwordProtected` | Web UI / WebDAV username |
| `AUTH_PASSWORD` | when `passwordProtected` | Web UI / WebDAV password (auth fails closed if unset) |
| `OPENROUTER_API_KEY` | for AI | OpenRouter API key |
| `MCP_TOKEN` | optional | Bearer token for `/mcp` (otherwise Basic auth is used) |

### ImpossibleCloud
`IMPOSSIBLE_ACCESS_KEY_ID`, `IMPOSSIBLE_SECRET_ACCESS_KEY`, `IMPOSSIBLE_BUCKET_NAME`,
`IMPOSSIBLE_REGION` (default `eu-central-2`).

### Wasabi
`WASABI_ACCESS_KEY_ID`, `WASABI_SECRET_ACCESS_KEY`, `WASABI_BUCKET_NAME`,
`WASABI_REGION` (default `us-east-1`).

### Cloudflare R2
`R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME`,
`R2_ACCOUNT_ID` (**required**), `R2_REGION` (default `auto`).

### Oracle Cloud (OCI)
`OCI_ACCESS_KEY_ID`, `OCI_SECRET_ACCESS_KEY`, `OCI_BUCKET_NAME`,
`OCI_NAMESPACE` (**required**), `OCI_REGION` (default `ap-hyderabad-1`).

> You only need credentials for the providers you actually use. A misconfigured provider is
> skipped during global search and cross-provider tools rather than breaking the request.

---

## 3. Security recommendations

- Set `AUTH_USERNAME` / `AUTH_PASSWORD` and `MCP_TOKEN` as **secrets**; keep `username`/`password` blank in code.
- Keep `debug: false` in production.
- Consider narrowing `corsAllowOrigin` from `"*"` to your own origin(s).
- Encrypt all provider secret keys.
- For public OCI share links, the bucket must be public; otherwise use CDN links.
