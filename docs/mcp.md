# Remote MCP Server Reference

The Worker exposes its 11 storage tools as a **remote [Model Context Protocol](https://modelcontextprotocol.io) server**, so any MCP client can list and call them.

- **Endpoint:** `POST https://<host>/mcp`
- **Transport:** stateless Streamable HTTP (JSON-RPC 2.0)
- **Protocol version advertised:** `2024-11-05`
- **Toggle:** `CONFIG.enableMCP` (default `true`)
- **No external dependencies** — reuses the existing `AGENT_TOOLS` registry and `executeAgentTool` dispatcher.

---

## 1. Authentication

The endpoint checks, in order:

1. **Bearer token** — `Authorization: Bearer <MCP_TOKEN>` (if the `MCP_TOKEN` secret is set).
2. **HTTP Basic** — the same `AUTH_USERNAME` / `AUTH_PASSWORD` used by the web UI.

If neither passes, the server responds `401` with a JSON-RPC error
`{ code: -32001, message: "Unauthorized" }`.

> `GET /mcp` returns an unauthenticated descriptor for discovery/health checks.

---

## 2. JSON-RPC methods

| Method | Description | Auth |
|--------|-------------|------|
| `initialize` | Handshake; returns `protocolVersion`, `capabilities`, `serverInfo` | yes |
| `ping` | Returns `{}` | yes |
| `tools/list` | Lists all tools with JSON-Schema `inputSchema` | yes |
| `tools/call` | Executes a tool: `params = { name, arguments }` | yes |
| `notifications/initialized` | Notification (no `id`) → `202`, no body | yes |

**Batches** (arrays of requests) are supported. **Notifications** (requests without `id`)
produce no response body (`202`).

### Error codes
| Code | Meaning |
|------|---------|
| `-32700` | Parse error (invalid JSON) |
| `-32600` | Invalid request (not JSON-RPC 2.0) |
| `-32601` | Method not found |
| `-32602` | Invalid params (e.g., unknown tool name) |
| `-32603` | Internal error (details hidden unless `CONFIG.debug`) |
| `-32001` | Unauthorized |

---

## 3. Examples

### initialize
```bash
curl -s https://$HOST/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```
```json
{ "jsonrpc": "2.0", "id": 1, "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": { "tools": { "listChanged": false } },
    "serverInfo": { "name": "multicloud-s3-mcp", "version": "7.0.0" } } }
```

### tools/list
```bash
curl -s https://$HOST/mcp -H "Authorization: Bearer $MCP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```
Returns `result.tools[]`, each `{ name, description, inputSchema }`.

### tools/call
```bash
curl -s https://$HOST/mcp -H "Authorization: Bearer $MCP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"search_files","arguments":{"query":"backup","fileType":"zip"}}}'
```
```json
{ "jsonrpc": "2.0", "id": 3, "result": {
    "content": [ { "type": "text", "text": "{ \"success\": true, \"totalFiles\": 3, ... }" } ],
    "isError": false } }
```
The tool's structured result is JSON-encoded inside `content[0].text`. `isError` is `true`
when the tool returned an `error` field.

---

## 4. Client setup

### Local clients via `mcp-remote`
Many desktop clients (Claude Desktop, Cursor, etc.) speak local stdio only. Bridge to the
remote server with [`mcp-remote`](https://www.npmjs.com/package/mcp-remote):

```json
{
  "mcpServers": {
    "multicloud-s3": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-worker.workers.dev/mcp",
        "--header", "Authorization: Bearer YOUR_MCP_TOKEN"
      ]
    }
  }
}
```

### Cloudflare AI Playground
Enter `https://your-worker.workers.dev/mcp` as a remote MCP server. Because the endpoint
uses bearer/basic auth (not OAuth), provide the credentials via the client's header config.

---

## 5. Notes & limitations

- **Stateless**: each call is independent; there is no server-side session state. This fits
  Workers well and avoids Durable Objects.
- **Link tools use the live origin**: `generate_links` builds URLs from the actual request
  origin, so links returned over MCP are valid for your deployment.
- **Safety**: destructive tools (`delete_files`, `move_files`, `batch_operations`) honor the
  `requireConfirmation` config and the per-tool `confirm` flag.
- **OAuth**: not implemented in the zero-dependency server. For OAuth consent flows, migrate
  to the Cloudflare Agents SDK (`workers-oauth-provider` + `McpAgent`) — see
  [migration.md](./migration.md).

See [agent-tools.md](./agent-tools.md) for every tool's parameters and return shape.
