# Migration Guide: Modular `src/` + Cloudflare Agents SDK (McpAgent)

This guide describes two larger, optional refactors. They are **not applied to the working
worker** because they require an `npm install` + a bundler/`wrangler` build that the current
authoring environment cannot run or verify. The single-file `multiclouds3 v7.0.js` remains
the canonical, dashboard-deployable artifact. Follow this guide when you adopt a build step.

---

## Part 1 — Split into `src/` modules

### Why
The 6.6k-line single file is hard to navigate and test. ES modules compile cleanly for
Workers via `wrangler deploy` (esbuild bundles them into one script). Trade-off: you lose the
"paste into dashboard" workflow (you now deploy with Wrangler).

### Proposed layout
```
src/
  index.js            # export default { fetch } — routing only
  config.js           # CONFIG, PROVIDERS
  http/
    cors.js           # handleOptions, addCorsHeaders
    auth.js           # checkAuth, getAuthCredentials, timingSafeEqual
    errors.js         # getErrorPage, HttpError
  util/
    escape.js         # escapeHtml, jsAttr, contentDisposition
    net.js            # fetchWithRetry, trimForModel
  s3/
    sign.js           # signRequest, generatePresignedUrl, crypto helpers
    list.js           # listObjects, parseListBucketResult, decodeS3Value
    ops.js            # s3CopyObject, s3UploadBody
  handlers/
    browse.js  download.js  stream.js  preview.js
    share.js   delete.js    search.js  bulk.js
  agent/
    tools.js          # AGENT_TOOLS, toJsonSchema, agentToolsForOpenAI
    execute.js        # executeAgentTool + all agent* implementations
    chat.js           # handleAIChat (OpenRouter loop)
    prompt.js         # buildAgenticSystemPrompt, parseToolRequest
  mcp/
    server.js         # handleMcp, handleMcpMessage
  ui/
    browse.page.js  login.page.js  search.page.js  (template strings)
test/
  *.test.mjs
```

### Steps
1. `npm init`; add `"type": "module"` (already set) and `wrangler` dev dep (already present).
2. Point `wrangler.toml` `main` at `src/index.js`.
3. Move each function group into its module; add `export`/`import`. Keep `CONFIG`/`PROVIDERS`
   in `config.js` and import where needed.
4. Replace cross-references (e.g. `escapeHtml`, `getProviderConfig`) with imports.
5. Run the existing `test/` suite (`node --test`) and `wrangler dev` to validate.
6. Optionally adopt **TypeScript** (`.ts` + `wrangler` supports it) for the signing/agent code.

### Notes
- Keep template-string UI in dedicated modules so escaping helpers are imported consistently.
- The test suite in `test/` imports the worker's default `fetch`; keep that export stable.

---

## Part 2 — Adopt the Cloudflare Agents SDK for MCP

The current MCP server is a zero-dependency JSON-RPC handler. Cloudflare's
[Agents SDK](https://developers.cloudflare.com/agents/) offers a higher-level option with
SSE **and** Streamable HTTP transports and OAuth.

| Approach | Use when | Infra |
|----------|----------|-------|
| Current zero-dep `/mcp` | No build step; bearer/basic auth is enough | none |
| `createMcpHandler` | Stateless server, want SDK ergonomics | plain Worker |
| `McpAgent` (class) | Need per-session state across calls | Durable Object |
| `+ workers-oauth-provider` | Need OAuth consent flows for clients | KV/DO |

Per Cloudflare's docs, `createMcpHandler` targets stateless API-style servers in a plain
Worker, while `McpAgent` persists state across requests via Durable Objects
([createMcpHandler](https://developers.cloudflare.com/agents/api-reference/mcp-handler-api),
[McpAgent](https://developers.cloudflare.com/agents/model-context-protocol/mcp-agent-api/)).
*Content was rephrased for compliance with licensing restrictions.*

### Sketch (stateful `McpAgent`)
```js
// src/mcp/agent.js
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { AGENT_TOOLS, executeAgentTool } from "../agent/execute.js";

export class StorageMcp extends McpAgent {
  server = new McpServer({ name: "multicloud-s3-mcp", version: "7.0.0" });
  async init() {
    // Reuse the same registry; map each tool's params to a zod schema.
    this.server.tool("search_files",
      { query: z.string(), provider: z.string().optional(), fileType: z.string().optional() },
      async (args) => {
        const r = await executeAgentTool("search_files", args, this.env, { origin: this.props.origin });
        return { content: [{ type: "text", text: JSON.stringify(r) }] };
      });
    // ...register the remaining tools the same way (or generate from AGENT_TOOLS)...
  }
}
```
```js
// src/index.js (excerpt)
export { StorageMcp };
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/sse")  return StorageMcp.serveSSE("/sse").fetch(request, env, ctx);
    if (url.pathname === "/mcp")  return StorageMcp.serve("/mcp").fetch(request, env, ctx);
    // ...existing routing...
  }
};
```
```toml
# wrangler.toml additions
[[durable_objects.bindings]]
name = "MCP_OBJECT"
class_name = "StorageMcp"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["StorageMcp"]
```

### Dependencies & cost
- `npm i agents @modelcontextprotocol/sdk zod` (and `workers-oauth-provider` for OAuth).
- `McpAgent` requires **Durable Objects** (Workers Paid plan).
- For auth, either keep the bearer/basic checks or wrap with `workers-oauth-provider`.

### Recommendation
Keep the zero-dependency `/mcp` for simple deployments. Move to `McpAgent` only when you need
per-session state, SSE transport, or OAuth — and after adopting the Wrangler build from Part 1.

---

## Why these weren't auto-applied here
- They require `npm install` + bundling/`wrangler`, which the current environment can't run,
  so the output couldn't be built or tested. Shipping an unverified large refactor would risk
  breaking a working worker. The single-file v7.0 + zero-dep MCP is fully tested instead
  (see [`test/`](../test)).
