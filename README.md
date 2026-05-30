# Multi-Cloud S3 Index for Cloudflare Workers

A unified, **CDN-powered**, serverless web interface to browse, preview, share, and delete files stored in **ImpossibleCloud**, **Wasabi**, **Cloudflare R2**, and **Oracle Cloud (OCI)** S3-compatible storage. Powered by Cloudflare Workers with advanced caching, optimization, and **autonomous AI agent** capabilities for intelligent file management.

> 🚀 **NEW v7.0:** Hardened security (env-based credentials, XSS-safe rendering), correct S3 pagination, a **remote MCP server** at `/mcp`, native AI tool-calling via OpenRouter, and fully-implemented `move`/`organize`/`batch` agent tools. See [What's New in v7.0](#-whats-new-in-v70).

-----

## ✨ Features

### **Core Functionality**
  - 📁 **Unified Browser:** Browse folders and files from ImpossibleCloud, Wasabi, Cloudflare R2, and Oracle Cloud under a single interface.
  - 🚀 **Automatic Routing:** Routes to the correct provider based on URL path prefixes (e.g., `/r2/`, `/oci/`, `/wasabi/`).
  - ⬇️ **Download & Stream:** Securely download or stream files, with support for browser-based video/audio playback.
  - 👁️ **Media Previews:** In-browser previews for images, videos (including enhanced MKV support), audio, and PDFs.
  - 🔗 **Dual Share Links:**
      - **🚀 CDN Link:** Worker URL with global CDN caching (perfect for small-medium files)
      - **🔗 Direct S3 Link:** Presigned or public URLs (best for large files or compatibility)
  - 🔍 **Global Search:** Search for files across all configured cloud providers simultaneously.
  - 📦 **Bulk Operations:** Select multiple files with checkboxes and perform bulk actions:
      - **Export Links:** Export CDN, Direct, or Download links in multiple formats (TXT, JSON, Markdown)
      - **Bulk Delete:** Delete multiple files at once with confirmation
  - 🗑️ **Delete Files:** Remove files directly from your buckets via the web interface (single or bulk).
  - 🔐 **WebDAV Authentication:** Secure username and password login (WebDAV-compatible Basic Auth).
  - 🎨 **Beautiful Themes:** 6 themes (Dark, Light, Blue, Purple, Sunset, Forest) with responsive mobile design.
  - 🌍 **Edge Deployment:** Deploy globally on the Cloudflare edge network for ultra-low latency.
  - 🔐 **Secure Signing:** Uses AWS Signature V4 for all S3 API requests.

### **🤖 Agentic AI Features** ⭐ **NEW in v6.8!**

Transform your storage management with an **autonomous AI agent** powered by Cloudflare Workers AI. The agent can understand natural language requests, reason through complex tasks, and **autonomously execute operations** across your multi-cloud storage.

#### **AI Agent Capabilities:**

**1. 🧠 Autonomous Intelligence**
  - **Natural Language Processing:** Ask questions in plain English
  - **Multi-Step Reasoning:** Agent plans and executes complex workflows automatically
  - **Tool Selection:** Intelligently chooses the right tools for each task
  - **Context Awareness:** Remembers conversation history (last 10 messages)
  - **Iterative Refinement:** Adapts based on results (up to 8 iterations)

**2. 🔧 11 Powerful Agent Tools:**

| Tool | Function | Status |
|------|----------|--------|
| **search_files** | Search across all providers with filters | ✅ Fully Working |
| **analyze_storage** | Complete storage analysis and statistics | ✅ Fully Working |
| **list_directory** | List files and folders in any path | ✅ Fully Working |
| **get_file_info** | Detailed metadata for specific files | ✅ Fully Working |
| **delete_files** | Safe deletion with confirmation | ✅ Fully Working |
| **generate_insights** | Data-driven recommendations | ✅ Fully Working |
| **generate_links** | All link types (4 formats) for files | ✅ Fully Working |
| **find_duplicates** | Find and delete duplicate files | ✅ Fully Working |
| **organize_files** | File organization suggestions | ⏳ Partial |
| **move_files** | Move/copy across providers | ⏳ Framework Ready |
| **batch_operations** | Complex batch workflows | ⏳ Framework Ready |

**3. 📊 Tool Details:**

**🔍 search_files**
  - Search across all providers or specific provider
  - Filter by file type (mp4, pdf, jpg, etc.)
  - Up to 3 directory levels deep
  - Returns up to 50 results with metadata

**📈 analyze_storage**
  - Total file count and storage size
  - Per-provider breakdown
  - Top 10 largest files
  - File type distribution
  - Formatted summary reports

**🔗 generate_links**
  - **Download Links:** Force download URLs
  - **Share Links:** Temporary presigned URLs (customizable expiry)
  - **Direct Links:** 7-day presigned or permanent public URLs
  - **Streaming Links:** CDN-accelerated with range request support
  - Generates all 4 types in one command!

**🔍 find_duplicates**
  - Scans all providers (up to 5 levels deep)
  - Groups by filename + size
  - Identifies which copies to keep/delete
  - Calculates potential space savings
  - Returns ready-to-delete list with safety checks

**💡 generate_insights**
  - **Large Files:** Find files over specified size
  - **Optimization:** Storage improvement suggestions
  - **Duplicates:** Duplicate file detection
  - **Old Files:** Identify rarely accessed files

**🗑️ delete_files**
  - Batch deletion with confirmation
  - Detailed success/failure reporting
  - Safety checks (requires confirm:true)
  - Works across all providers

**4. 💬 Example Commands:**

```
"Find all MP4 files in Wasabi"
"Analyze my storage usage across all providers"
"Generate all links for video.mp4"
"Find and delete duplicate files"
"What are my largest files?"
"Search for PDFs larger than 10MB"
"Give me a 24-hour share link for document.pdf"
"Find duplicates and show how much space I can save"
"List everything in the videos folder"
"How can I optimize my storage?"
```

**5. 🎯 Multi-Step Workflow Examples:**

**Storage Audit:**
```
You: "Audit my storage and find duplicates"

Agent automatically:
1. Analyzes storage across all providers
2. Finds duplicate file groups
3. Generates insights
4. Reports: "128.5 GB total, 1,247 files, 8 duplicate groups (2.3 GB savings)"
```

**Find & Delete Duplicates:**
```
You: "Find and delete duplicate files"

Agent:
1. Scans all providers
2. Shows: "Found 12 duplicates, can save 2.3 GB"
3. You: "yes"
4. Deletes files with confirmation
5. Reports: "Deleted 12 files, freed 2.3 GB"
```

**Bulk Link Generation:**
```
You: "Find all my videos and generate streaming links"

Agent:
1. Searches for video files (mp4, mkv, avi)
2. Finds 45 videos across providers
3. Generates streaming URLs for all
4. Returns ready-to-use links
```

**6. ⚡ Agent Features:**

  - **Autonomous Execution:** Takes action automatically (with safety checks)
  - **Tool Chaining:** Combines multiple tools for complex tasks
  - **Smart Recommendations:** Data-driven insights with actionable advice
  - **Visual Feedback:** Shows tool usage: "🔧 Agent used 3 tool(s) in 2 step(s)"
  - **Conversation Memory:** Understands context and follow-up questions
  - **Error Handling:** Graceful degradation with helpful error messages

**7. 🛡️ Safety Features:**

  - Confirmation required for destructive operations
  - Auto-execution can be disabled (`enableAutoExecution: false`)
  - Iteration limits prevent runaway processes (max 8)
  - Detailed logging for transparency
  - Tool-level safety checks

**8. ⚙️ AI Configuration:**

```javascript
enableAIChat: true,
aiProvider: "openrouter",            // AI is powered by OpenRouter
aiModel: "minimax/minimax-m2:free",  // any OpenRouter model id
enableAgenticAI: true,
agentConfig: {
  maxIterations: 8,
  enableAutoExecution: true,
  requireConfirmation: false, // Set true to require confirm:true before destructive tools run
  tools: [/* 11 tools enabled */]
}
```

> The AI agent uses **OpenRouter** (set the `OPENROUTER_API_KEY` secret), not the Cloudflare AI binding. It uses **native function/tool calling** with a text-protocol fallback for models that don't support tools.

### **🔐 WebDAV Authentication** ⭐ **NEW in v6.8!**

Secure your storage with WebDAV-compatible username and password authentication.

**Features:**
  - 🔒 **HTTP Basic Authentication** - Industry standard WebDAV protocol
  - 👤 **Username + Password** - Dual credential authentication
  - 🎨 **Beautiful Login Page** - Modern, responsive design with gradient background
  - 💾 **Session Persistence** - Credentials stored in session for convenience
  - 🌐 **WebDAV Client Compatible** - Works with rclone, Cyberduck, Windows Explorer
  - ⚠️ **Failed Login Feedback** - Clear error messages for invalid credentials

**Configuration (v7.0):**
```javascript
passwordProtected: true,
authMode: "username", // "username" (WebDAV) or "password" (legacy)
// Credentials are read from Worker SECRETS, not the source file:
//   AUTH_USERNAME, AUTH_PASSWORD
// The in-code username/password fields are blank fallbacks for local testing only.
```
> 🔐 **Security:** In v7.0 credentials are no longer hard-coded. Set them as secrets
> (`wrangler secret put AUTH_USERNAME` / `AUTH_PASSWORD`). If neither the secret nor a
> code fallback is set, authentication **fails closed** (access denied). Comparisons are
> constant-time.

**Compatible with:**
  - **rclone** - WebDAV backend with Basic Auth
  - **Cyberduck / Transmit** - WebDAV connections
  - **Windows Explorer** - Map network drive
  - **macOS Finder** - Connect to Server
  - **Linux davfs2** - Mount as filesystem
  - **Mobile Apps** - FolderSync, WebDAV Navigator

**Login Experience:**
  - Elegant card-based design
  - Smooth animations
  - Real-time validation
  - Mobile responsive
  - Auto-focus and keyboard shortcuts
  - Security badge display

### **🚀 Performance Features**
  - ⚡ **Range Request Caching:** Seeks/scrubbing in MX Player/VLC are **10x faster** after first view
  - 🎯 **Smart Link Recommendations:** Visual indicators (✨ sparkle) show which button to use based on file size
  - 📊 **Intelligent Caching:** Small files cached for 2 hours, large files for 30 minutes
  - 🎬 **HLS Segment Prefetching:** Automatically prefetches next video segment for buffer-free playback
  - 📈 **Performance Headers:** See response times and cache status in browser DevTools
  - 😊 **User-Friendly Errors:** Clear, actionable error messages instead of technical jargon
  - 📱 **Mobile Optimization:** Detects mobile devices and provides helpful guidance
  - 🗜️ **Auto Compression:** Cloudflare automatically compresses text/JSON responses

-----

## 📋 Prerequisites

  - A Cloudflare account with Workers enabled ([Dashboard](https://dash.cloudflare.com))
  - **Cloudflare AI binding** for agentic features (free tier available)
  - An **ImpossibleCloud** account and storage bucket (optional)
  - A **Wasabi** account and storage bucket (optional)
  - A **Cloudflare R2** bucket and S3 credentials (optional)
  - An **Oracle Cloud (OCI)** account, bucket, and S3 credentials (optional)

-----

## 🚀 Setup Instructions

### 1\. Obtain API Keys and Buckets

For each provider you want to use, gather the following credentials:

#### ImpossibleCloud

  - Create a bucket and generate S3 access keys.
  - Note your: **Access Key ID**, **Secret Access Key**, **Bucket Name**, and **Region**.

#### Wasabi

  - Create a bucket and generate S3 access keys.
  - Note your: **Access Key ID**, **Secret Access Key**, **Bucket Name**, and **Region**.

#### Cloudflare R2

  - Create a bucket in the R2 dashboard.
  - Create an "R2 API Token" with *Read & Write* permissions.
  - Note your: **Access Key ID**, **Secret Access Key**, **Bucket Name**, and your **Account ID** (found on the main R2 page).

#### Oracle Cloud (OCI)

  - Create a bucket (set it to **Public** if you want to use the public share link feature).
  - Go to your User settings → Customer Secret Keys and generate a new key.
  - Note your: **Access Key ID**, **Secret Access Key**, and **Bucket Name**.
  - Find your tenancy's unique **Namespace** (Go to Object Storage → click any bucket → see "Namespace" in the details).
  - Note your **Region** (e.g., `ap-hyderabad-1`).

### 2\. Deploy the Worker

**Option A — Dashboard (no build):**
  - Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com) → Workers & Pages → Create Worker.
  - Copy and paste the complete worker code (`multiclouds3 v7.0.js`).
  - Save and deploy.

**Option B — Wrangler (recommended):**
```bash
npm install
npx wrangler deploy        # uses wrangler.toml (main = "multiclouds3 v7.0.js")
```

### 3\. Configure Environment Variables & Secrets

Add the following. With Wrangler, set sensitive values as **secrets**
(`npx wrangler secret put NAME`); in the dashboard, use **Encrypt**. You only need
variables for the providers you use.

#### Authentication, AI & MCP (set as secrets)

| Variable Name | Required | Description |
| --- | --- | --- |
| `AUTH_USERNAME` | yes* | Web UI / WebDAV login username (replaces hard-coded CONFIG value) |
| `AUTH_PASSWORD` | yes* | Web UI / WebDAV login password (auth fails closed if unset) |
| `OPENROUTER_API_KEY` | for AI | OpenRouter API key that powers the AI agent |
| `MCP_TOKEN` | optional | Bearer token for the `/mcp` endpoint (otherwise Basic auth is used) |

\* Required when `passwordProtected: true` (the default).

#### Provider credentials

| Variable Name | Example Value | Description |
| --- | --- | --- |
| `IMPOSSIBLE_ACCESS_KEY_ID` | `E66C5D15FDEAA3EE...` | ImpossibleCloud Access Key |
| `IMPOSSIBLE_SECRET_ACCESS_KEY` | `ad8fb4f17ce235c69...` | ImpossibleCloud Secret Key |
| `IMPOSSIBLE_BUCKET_NAME` | `my-impossible-bucket` | ImpossibleCloud Bucket Name |
| `IMPOSSIBLE_REGION` | `eu-central-2` | ImpossibleCloud Region |
| `WASABI_ACCESS_KEY_ID` | `B75P0FDJF41RI...` | Wasabi Access Key |
| `WASABI_SECRET_ACCESS_KEY` | `3z7ZCpDwQ0nMdbB...` | Wasabi Secret Key |
| `WASABI_BUCKET_NAME` | `my-wasabi-bucket` | Wasabi Bucket Name |
| `WASABI_REGION` | `ap-northeast-1` | Wasabi Region |
| `R2_ACCESS_KEY_ID` | `a0b1c2d3e4f5...` | Cloudflare R2 Access Key |
| `R2_SECRET_ACCESS_KEY` | `g6h7j8k9l0m1...` | Cloudflare R2 Secret Key |
| `R2_BUCKET_NAME` | `my-r2-bucket` | Cloudflare R2 Bucket Name |
| `R2_ACCOUNT_ID` | `f9e8d7c6b5a4...` | **Required for R2.** Your Cloudflare Account ID |
| `OCI_ACCESS_KEY_ID` | `OCI...` | Oracle Cloud Access Key |
| `OCI_SECRET_ACCESS_KEY` | `zYxWvU...` | Oracle Cloud Secret Key |
| `OCI_BUCKET_NAME` | `my-oci-bucket` | Oracle Cloud Bucket Name |
| `OCI_NAMESPACE` | `axbycz...` | **Required for OCI.** Your OCI Tenancy Namespace |
| `OCI_REGION` | `ap-hyderabad-1` | Oracle Cloud Region |

**Important:** Always store **Secret Access Keys** and tokens as encrypted secrets.

### 4\. Configure the AI Agent (OpenRouter)

The AI agent is powered by [OpenRouter](https://openrouter.ai) (not the Cloudflare AI
binding). Create an API key and set it as a secret:

```bash
npx wrangler secret put OPENROUTER_API_KEY
```

Pick any model via `CONFIG.aiModel` (default `minimax/minimax-m2:free`). The agent uses
native tool-calling when the model supports it and falls back to a text protocol otherwise.

### 5\. Configure Authentication

Set credentials as secrets (do **not** put them in the source):

```bash
npx wrangler secret put AUTH_USERNAME
npx wrangler secret put AUTH_PASSWORD
```

In `CONFIG`, keep `passwordProtected: true` and choose `authMode: "username"` (WebDAV) or
`"password"` (legacy). Leave `username`/`password` blank in code.

### 6\. Access Your Interface

  - Visit your Worker URL (e.g., `https://multi-cloud.my-worker.workers.dev/`).
  - Log in with your credentials.
  - The interface will show buttons to navigate to each provider's root:
      - `/impossible/` → Browses ImpossibleCloud
      - `/wasabi/` → Browses Wasabi
      - `/r2/` → Browses Cloudflare R2
      - `/oci/` → Browses Oracle Cloud
  - Click the **🤖 AI Agent ⚡** button to access the autonomous assistant.

-----

## 🤖 Using the AI Agent

### **Quick Start:**

1. **Click** the "🤖 AI Agent ⚡" button in the interface
2. **Type** your request in natural language
3. **Watch** the agent autonomously execute tools
4. **Get** intelligent results with actionable insights

### **Example Workflows:**

**Simple Queries:**
```
"Find all MP4 files"
"What's my largest file?"
"How much storage am I using?"
```

**Complex Analysis:**
```
"Analyze storage and suggest optimizations"
"Find files older than 6 months over 1GB"
"Compare usage across all providers"
```

**Multi-Step Tasks:**
```
"Find duplicate files and calculate space savings"
→ Agent uses find_duplicates tool
→ Shows: "Found 8 duplicate groups, can save 2.3 GB"

"Delete them"
→ Agent uses delete_files with confirmation
→ Executes deletion
→ Reports: "Deleted 12 files, freed 2.3 GB"
```

**Link Generation:**
```
"Generate all links for video.mp4 in Wasabi"
→ Agent uses generate_links tool
→ Returns:
  • Download Link
  • Share Link (1 hour expiry)
  • Direct Link (7 days)
  • Streaming Link (CDN)
```

**Follow-Up Conversations:**
```
You: "Find MP4 files"
Agent: "Found 48 files..."

You: "Show me the largest ones"
Agent: [remembers context, filters by size]

You: "Delete files over 2GB"
Agent: [asks confirmation, executes]
```

### **Tool Usage Transparency:**

The agent shows what it's doing:
```
🔧 Agent used 3 tool(s) in 2 step(s)
```

See detailed logs in browser console:
```
[Agent] Processing request: Find duplicates
[Agent] Executing tool: find_duplicates
[Agent] Found 127 total files
[Agent] Found 8 duplicate groups
```

-----

## 🔌 Remote MCP Server (v7.0)

The same 11 agent tools are exposed as a **remote [Model Context Protocol](https://modelcontextprotocol.io) server** so any MCP client (Claude Desktop, Cursor, the Cloudflare AI Playground, etc.) can list and call them.

  - **Endpoint:** `POST https://your-worker.workers.dev/mcp`
  - **Transport:** stateless Streamable HTTP, JSON-RPC 2.0 (no extra infrastructure, no dependencies)
  - **Methods:** `initialize`, `ping`, `tools/list`, `tools/call`
  - **Toggle:** `CONFIG.enableMCP` (default `true`)

### Authentication

Two options (the bearer token is checked first, then Basic auth):

  - **Bearer token (recommended for clients):** set the `MCP_TOKEN` secret and send `Authorization: Bearer <token>`.
  - **Basic auth:** reuse your `AUTH_USERNAME` / `AUTH_PASSWORD` (works with header pass-through).

### Quick test

```bash
# List tools
curl -s https://your-worker.workers.dev/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Call a tool
curl -s https://your-worker.workers.dev/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"analyze_storage","arguments":{"provider":"all"}}}'
```

### Connect from a local MCP client

For clients that only speak local stdio, bridge to the remote server with
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote):

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

> Tools that generate links use the live request origin, so URLs returned over MCP are valid for your deployment.

-----

## 🎯 Using the Dual Share Buttons

Each file now has **TWO share buttons** with smart recommendations:

### **🚀 CDN Link Button (Green)**
- **What it does:** Copies a Worker URL that goes through Cloudflare's CDN
- **Best for:** 
  - Files under 1 GB
  - Videos you'll watch multiple times
  - Sharing with multiple people
- **Benefits:**
  - ⚡ **10x faster** after first load (cached globally)
  - Perfect for MX Player, VLC, Kodi
  - Instant seeking after initial cache
- **Visual indicator:** ✨ Sparkles and glows for recommended files

### **🔗 Direct S3 Link Button (Orange)**
- **What it does:** Copies a direct S3 URL (presigned or public)
- **Best for:**
  - Files over 1 GB
  - One-time downloads
  - Maximum compatibility
- **Benefits:**
  - No proxy overhead
  - Works for any file size
  - 7-day expiration (or permanent for public OCI buckets)
- **Visual indicator:** ✨ Sparkles and glows for large files (>1GB)

### **How to Choose:**
```
File Size < 1 GB:     Use 🚀 CDN (it will glow ✨)
File Size ≥ 1 GB:     Use 🔗 Direct (it will glow ✨)
Repeated viewing:     Use 🚀 CDN
One-time download:    Use 🔗 Direct
MX Player (small):    Use 🚀 CDN
MX Player (large):    Use 🔗 Direct
```

**Or just ask the AI Agent:**
```
"Generate all links for this file"
→ Returns all 4 link types with recommendations
```

-----

## 🔍 Global Search

Search for files across **all your configured cloud providers** simultaneously!

### **How to Use:**
1. Use the search box at the top of the interface
2. Enter your search term (minimum 2 characters)
3. Results show files from ImpossibleCloud, Wasabi, R2, and OCI together
4. Each result displays:
   - File name, size, and last modified date
   - Provider icon and name
   - Direct actions (Preview, Download, Share, Delete)

### **Or Use the AI Agent:**
```
"Search for all PDF files"
"Find videos larger than 1GB"
"Look for files with 'backup' in the name"
```

The agent uses the `search_files` tool automatically!

-----

## 📦 Bulk Operations

Select multiple files and perform batch operations with ease!

### **Bulk Export Links**
Export file links in 6 formats: CDN, Direct, Download, All, JSON, Markdown

**Or use AI Agent:**
```
"Generate download links for all PDFs"
"Create streaming links for all videos in Wasabi"
```

### **Bulk Delete**
Delete multiple files at once with confirmation

**Or use AI Agent:**
```
"Delete all files older than 1 year"
"Find and delete duplicates"
"Remove backup files from last month"
```

The agent handles safety checks and confirmation automatically!

-----

## ⚙️ Configuration Options

Edit the `CONFIG` object at the top of the Worker code to customize your deployment.

```js
const CONFIG = {
  siteName: "Multi-Cloud S3 Index",
  siteIcon: "🌤️",
  theme: "dark", // "dark", "light", "blue", "purple", "sunset", "forest"
  
  // Authentication (credentials come from secrets AUTH_USERNAME / AUTH_PASSWORD)
  passwordProtected: true,
  authMode: "username", // "username" (WebDAV) or "password" (legacy)
  username: "",         // leave blank; set AUTH_USERNAME secret instead
  password: "",         // leave blank; set AUTH_PASSWORD secret instead

  // Security / networking (v7.0)
  corsAllowOrigin: "*", // tighten to your origin(s) for stricter CORS
  debug: false,         // true exposes technical error details (never in prod)
  enableMCP: true,      // expose the agent tools as a remote MCP server at /mcp
  
  // AI Agent (OpenRouter — set OPENROUTER_API_KEY secret)
  enableAIChat: true,
  aiProvider: "openrouter",
  aiModel: "minimax/minimax-m2:free",
  enableAgenticAI: true,
  agentConfig: {
    maxIterations: 8,
    enableAutoExecution: true,  // Allow agent to execute operations
    requireConfirmation: false, // true => destructive tools require confirm:true
    tools: [/* 11 tools */]
  },
  
  // Storage
  experimentalMkvSupport: true,
  routingStrategy: "path-based",
  pathRouting: {
    "impossible/": "impossiblecloud",
    "wasabi/": "wasabi",
    "r2/": "cloudflarer2",
    "oci/": "oraclecloud",
    default: "impossiblecloud"
  },
  providerPriority: ["impossiblecloud", "wasabi", "cloudflarer2", "oraclecloud"],
  
  // Search
  enableGlobalSearch: true,
  searchCacheTime: 300, // 5 minutes
  
  // Sorting
  defaultSort: { field: "name", direction: "asc" }
};
```

-----

## 🆕 What's New in v7.0

A correctness, security, and integration release.

### 🔒 Security
  - **Credentials moved out of source** → read from `AUTH_USERNAME` / `AUTH_PASSWORD` secrets; auth **fails closed** if unset.
  - **Constant-time** credential comparison; correct handling of passwords containing `:`.
  - **XSS-safe rendering** — all file/folder names, paths, and search queries are HTML/JS-escaped in the browse and search pages (previously a stored-XSS risk via crafted filenames).
  - **No info leakage** — stack traces and raw upstream error text are gated behind `CONFIG.debug`.
  - **Tighter CORS** — cross-origin `DELETE` is no longer pre-authorized; `/mcp` preflight allows `POST`.
  - **Confirmation gate** — `requireConfirmation` is now actually enforced for destructive agent tools.

### 🐞 Correctness
  - **S3 pagination** — listings now follow `NextContinuationToken` (previously truncated at 1000 objects everywhere).
  - **Correct key decoding** — `encoding-type=url` + entity/URL decoding fixes names containing `&`, spaces, etc.
  - **Range-cache fix** — partial (206) responses are no longer cached under the full-object key.
  - **`generate_links` fixed** — uses the real request origin instead of a hard-coded placeholder.
  - Agent file ops now strip routing prefixes so deletes/moves target the correct key.

### 🤖 AI & 🔌 MCP
  - **OpenRouter** with **native function/tool calling** (text-protocol fallback retained).
  - **ETag-based duplicate detection** (content hash) with name+size fallback.
  - **Retry/backoff + timeouts** on upstream calls; large tool outputs trimmed before re-feeding the model.
  - **Remote MCP server** at `/mcp` (see above).
  - **Implemented** `move_files` (same-provider server-side copy; cross-provider stream), `organize_files` (preview + execute), and `batch_operations` (delete/move/links/list by criteria).

### 🛠️ Project
  - Added `wrangler.toml`, `package.json`, and `.gitignore` for a proper build/deploy workflow (the single-file dashboard paste still works).

-----

## 🆕 What's New in v6.8

### **Agentic AI System** 🤖

Complete autonomous agent implementation:

**11 Agent Tools:**
1. ✅ **search_files** - Cross-provider search with filters
2. ✅ **analyze_storage** - Complete storage analysis
3. ✅ **list_directory** - Directory listing
4. ✅ **get_file_info** - File metadata
5. ✅ **delete_files** - Safe deletion
6. ✅ **generate_insights** - Data-driven recommendations
7. ✅ **generate_links** - All link types (4 formats)
8. ✅ **find_duplicates** - Duplicate detection & deletion
9. ⏳ **organize_files** - Organization suggestions
10. ⏳ **move_files** - Cross-provider moves
11. ⏳ **batch_operations** - Complex workflows

**Agent Capabilities:**
- 🧠 Natural language understanding
- 🔄 Multi-step reasoning (up to 8 iterations)
- 🎯 Autonomous tool selection
- 💬 Conversation memory
- ⚡ Automatic execution with safety checks
- 📊 Transparent operation logging

**Example Agent Tasks:**
```
✓ Find and delete duplicates → Saves 2.3 GB
✓ Analyze storage and optimize → 3 actionable recommendations
✓ Generate all links for file → 4 link types in one command
✓ Search across providers → Results from all clouds
✓ Complex multi-step workflows → Fully automated
```

### **WebDAV Authentication** 🔐

Professional username + password login:

- 🎨 Beautiful login page with gradient design
- 👤 Username and password fields
- 🔒 HTTP Basic Authentication (WebDAV standard)
- 💾 Session persistence
- 🌐 Compatible with rclone, Cyberduck, Windows Explorer
- ⚠️ Real-time error feedback
- 📱 Mobile responsive

### **Enhanced Duplicate Detection** 🔍

Powered by AI agent's `find_duplicates` tool:

- Scans up to 5 directory levels
- Groups by filename + size
- Calculates space savings
- Smart keep/delete selection
- Cross-provider duplicate detection
- Detailed reporting

### **Link Generation** 🔗

AI agent's `generate_links` tool provides:

- **Download Links** - Force download
- **Share Links** - Temporary presigned (customizable expiry)
- **Direct Links** - 7-day or permanent
- **Streaming Links** - CDN-accelerated

All 4 types in one command!

-----

## 📊 AI Agent vs Manual Operations

| Task | Manual | With AI Agent |
|------|--------|---------------|
| Find duplicates | Search → Compare → List → Delete | "Find and delete duplicates" → Done |
| Generate links | Click each file → Copy 4 links | "Generate all links" → All 4 types ready |
| Storage analysis | Browse → Calculate → Organize | "Analyze my storage" → Complete report |
| Complex search | Multiple searches → Filter → Sort | "Find MP4s over 1GB in Wasabi" → Results |
| Bulk operations | Select → Export → Format → Copy | "Export links for all videos" → Done |
| Optimization | Manual review → Research → Plan | "Optimize my storage" → Actionable plan |

**Time Saved:** Up to **90% faster** for complex tasks!

-----

## 🔧 Troubleshooting

### **AI Agent**
  - **Agent not responding:** Ensure the `OPENROUTER_API_KEY` secret is set and the model id in `CONFIG.aiModel` is valid
  - **Tools not executing:** Verify `enableAgenticAI: true` in CONFIG; some free models don't support native tool-calling (the text-protocol fallback then applies)
  - **Hitting iteration limit:** Increase `maxIterations` or break into smaller tasks
  - **Delete not working:** Check `enableAutoExecution: true` (and pass `confirm:true` when `requireConfirmation` is enabled)
  - **No duplicates found:** Agent scans up to 5 levels and caps at 20,000 files - files may be deeper

### **MCP Server**
  - **401 from `/mcp`:** Send `Authorization: Bearer <MCP_TOKEN>` or valid Basic credentials
  - **Disabled:** Ensure `enableMCP: true` in CONFIG
  - **Local client can't connect:** Bridge with `npx mcp-remote <url>/mcp` and pass the auth header

### **WebDAV Authentication**
  - **Login fails:** Check the `AUTH_USERNAME` / `AUTH_PASSWORD` secrets match exactly
  - **Session expires:** Credentials stored in sessionStorage (cleared on browser close)
  - **rclone can't connect:** Ensure `authMode: "username"` is set
  - **Still prompts for password:** Clear browser cache and session storage

### **Authentication & Configuration**
  - **Authentication Errors:** Double-check your keys, regions, and bucket names. For R2, ensure `R2_ACCOUNT_ID` is set. For OCI, ensure `OCI_NAMESPACE` is set.
  - **OCI Public Links Not Working:** Direct links for OCI require public bucket. For private buckets, use CDN links.
  - **Delete Failed:** S3 keys need `s3:DeleteObject` permissions.

### **Performance & Caching**
  - **CDN Link Not Fast:** First access fetches from S3. Subsequent accesses are cached and instant.
  - **Large Files Slow with CDN:** Use 🔗 Direct button for files over 1 GB.
  - **Cache Not Working:** Check DevTools → Network → Headers for `CF-Cache-Status: HIT`

### **Global Search & Bulk Operations**
  - **Search Not Working:** Ensure `enableGlobalSearch: true` in CONFIG
  - **Bulk Export Fails:** Check provider credentials and permissions
  - **Presigned URLs Invalid:** Direct links expire after 7 days

-----

## 🚀 Why Use This?

### **vs. Manual File Management:**
- ✅ **AI-Powered Automation** - Natural language commands
- ✅ **90% Time Savings** - Complex tasks automated
- ✅ **Intelligent Insights** - Data-driven recommendations
- ✅ **Multi-Provider** - Single interface for all clouds
- ✅ **No Manual Work** - Agent handles repetitive tasks

### **vs. Paid CDN Services:**
- ✅ **100% FREE** (Cloudflare Workers + AI free tier)
- ✅ Global edge network (250+ locations)
- ✅ No bandwidth fees
- ✅ AI agent included
- ✅ No lock-in

### **vs. Traditional WebDAV:**
- ✅ **Modern UI** - Beautiful web interface
- ✅ **AI Assistant** - Intelligent file management
- ✅ **CDN Acceleration** - 10x faster streaming
- ✅ **Multi-Cloud** - All providers in one place
- ✅ **WebDAV Compatible** - Works with all clients

-----

## 💡 Use Cases

### **Perfect For:**
  - 🎬 **Media Libraries** - AI-powered organization and streaming
  - 📦 **File Sharing** - Intelligent link generation
  - 🗄️ **Backup Management** - Duplicate detection and cleanup
  - 📱 **Mobile Streaming** - Optimized links for MX Player/VLC
  - 🏢 **Team Collaboration** - Multi-cloud access with AI assistant
  - 🎮 **Game Assets** - Fast CDN delivery with intelligent caching
  - 📚 **Document Archives** - Smart search and organization

### **AI Agent Examples:**

**Home Media Server:**
```
"Find duplicate movies and TV shows"
"Generate streaming links for all episodes"
"What's taking up the most space?"
"Organize media files by type"
```

**Backup Management:**
```
"Find backups older than 6 months"
"Delete duplicate backup files"
"Analyze backup storage usage"
"Generate download links for recent backups"
```

**Content Distribution:**
```
"Find all videos over 100MB"
"Generate CDN links for distribution"
"What's my most accessed file?"
"Create share links that expire in 24 hours"
```

-----

## 🌟 Feature Comparison

| Feature | v6.2 | v6.8 |
|---------|------|------|
| Multi-cloud browse | ✅ | ✅ |
| Global search | ✅ | ✅ |
| Bulk operations | ✅ | ✅ |
| Authentication | No  | **WebDAV (Username + Password)** |
| AI Assistant | ❌ | **✅ 11 Autonomous Tools** |
| Duplicate detection | Manual | **✅ AI-Powered** |
| Link generation | Manual (1 at a time) | **✅ All 4 types in 1 command** |
| Storage analysis | Basic stats | **✅ AI Insights** |
| Natural language | ❌ | **✅ Full support** |
| Multi-step workflows | Manual | **✅ Autonomous** |

-----

## License

MIT License - Free to use, modify, and distribute.

-----

## Credits & Acknowledgments

### **Built With:**
  - [Cloudflare Workers](https://developers.cloudflare.com/workers) - Serverless edge computing
  - [Cloudflare Workers AI](https://developers.cloudflare.com/workers-ai/) - Autonomous AI agent
  - [Cloudflare CDN](https://www.cloudflare.com/cdn/) - Global content delivery network

### **Compatible Storage Providers:**
  - [ImpossibleCloud](https://impossiblecloud.com) - European S3-compatible storage
  - [Wasabi Hot Cloud Storage](https://wasabi.com) - Global hot cloud storage
  - [Cloudflare R2](https://www.cloudflare.com/products/r2/) - Zero-egress S3-compatible storage
  - [Oracle Cloud Infrastructure](https://www.oracle.com/cloud/) - OCI Object Storage

-----

## 🌟 Star This Project

If you find this useful, please consider starring the repository! It helps others discover this tool.

---

**Made with ❤️ and 🤖 AI for the self-hosting community**

*Enjoy your blazing-fast, CDN-powered, AI-enhanced, multi-cloud file browser!* 🚀

**Version 7.0** - Hardened security, correct S3 pagination, OpenRouter AI with native tool-calling, and a remote MCP server
