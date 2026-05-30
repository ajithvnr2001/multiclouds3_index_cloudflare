# Deployment

Two supported workflows. Both deploy the same `multiclouds3 v7.0.js` module.

---

## Option A — Wrangler (recommended)

Prerequisites: Node.js 18+ and a Cloudflare account.

```bash
# 1. Install dev dependency (wrangler)
npm install

# 2. Authenticate
npx wrangler login

# 3. Set secrets (prompts for the value)
npx wrangler secret put AUTH_USERNAME
npx wrangler secret put AUTH_PASSWORD
npx wrangler secret put OPENROUTER_API_KEY     # for the AI agent
npx wrangler secret put MCP_TOKEN              # optional, for /mcp

# Provider credentials (set the ones you use)
npx wrangler secret put WASABI_ACCESS_KEY_ID
npx wrangler secret put WASABI_SECRET_ACCESS_KEY
npx wrangler secret put WASABI_BUCKET_NAME
# ... Impossible / R2 / OCI equivalents

# 4. Deploy
npx wrangler deploy
```

`wrangler.toml` already points `main` at `multiclouds3 v7.0.js` and sets a
`compatibility_date`. Non-secret values (e.g. regions) can be added under `[vars]` or set as
plain dashboard variables.

Local development:
```bash
npx wrangler dev          # http://localhost:8787
```
Put local secrets in a `.dev.vars` file (git-ignored), e.g.:
```
AUTH_USERNAME=admin
AUTH_PASSWORD=devpass
OPENROUTER_API_KEY=sk-or-...
WASABI_ACCESS_KEY_ID=...
```

---

## Option B — Dashboard (no build)

1. Cloudflare Dashboard → **Workers & Pages** → **Create Worker**.
2. Replace the code with the full contents of `multiclouds3 v7.0.js`. Save & Deploy.
3. **Settings → Variables**: add the environment variables/secrets from
   [configuration.md](./configuration.md). Use **Encrypt** for all keys, passwords, and tokens.
4. Visit the Worker URL and log in.

> The Worker uses only Web-standard APIs, so no bindings, build step, or compatibility flags
> are required. (The AI agent uses OpenRouter over HTTPS, **not** the Cloudflare AI binding.)

---

## Post-deploy checklist

- [ ] `AUTH_USERNAME` / `AUTH_PASSWORD` set — confirm the login page appears and accepts them.
- [ ] At least one provider's credentials set — confirm browsing works (`/wasabi/`, etc.).
- [ ] `OPENROUTER_API_KEY` set — open the AI panel and send a test message.
- [ ] `MCP_TOKEN` set (if using MCP) — `curl` `tools/list` (see [mcp.md](./mcp.md)).
- [ ] `R2_ACCOUNT_ID` set if using R2; `OCI_NAMESPACE` set if using OCI.
- [ ] `debug: false` in `CONFIG`.

---

## Verifying the deployment

```bash
HOST=your-worker.your-account.workers.dev

# Auth required
curl -s -o /dev/null -w "%{http_code}\n" https://$HOST/wasabi/        # 401

# Browse (authenticated)
curl -s -u "$USER:$PASS" https://$HOST/wasabi/ | head -c 200

# MCP tools list
curl -s https://$HOST/mcp -H "Authorization: Bearer $MCP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -c 400
```

---

## CI

`.github/workflows/ci.yml` runs `node --check` and the zero-dependency test suite
(`node --test`) on every push/PR. See [`test/`](../test). No secrets are needed for CI;
provider/network calls are mocked.

---

## Rollback

Each Wrangler deploy creates a version. Roll back from the dashboard
(**Workers → your worker → Deployments**) or with `npx wrangler rollback`.
