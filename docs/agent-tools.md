# Agent Tools Reference

The AI agent and the [MCP server](./mcp.md) share one registry, `AGENT_TOOLS`, dispatched by
`executeAgentTool(name, args, env, { origin })`. All 11 tools are listed below with their
parameters, behavior, safety, and return shape.

> **Path convention.** Tools accept file references as `{ provider, path }`. `path` may
> include the routing prefix (e.g. `wasabi/videos/a.mp4`); the dispatcher strips it before
> S3 calls. `provider` is the internal id: `impossiblecloud | wasabi | cloudflarer2 | oraclecloud`.

> **Safety.** When `CONFIG.agentConfig.requireConfirmation` is `true`, the destructive tools
> (`delete_files`, `move_files`, `batch_operations`) require `confirm: true` in their args.
> `enableAutoExecution: false` disables all write operations.

---

## search_files
Search across all providers (or one) by filename substring, optionally filtered by extension.

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `query` | string | ✅ | Filename substring (case-insensitive) |
| `provider` | string | – | Limit to one provider id |
| `fileType` | string | – | Extension filter, e.g. `mp4`, `pdf` |

Recurses up to 3 levels; returns up to 50 results.
**Returns:** `{ success, totalFiles, files:[{ name, key, path, size, etag, modified }], query }`

---

## analyze_storage
Aggregate usage across providers.

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `provider` | string | – | One provider id or `all` (default) |
| `depth` | number | – | Directory depth to analyze (1–3) |

**Returns:** `{ success, analysis: { providers, totalFiles, totalSize, largestFiles[], fileTypes{} }, formatted }`

---

## list_directory
List one folder.

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `path` | string | ✅ | Directory path |
| `provider` | string | ✅ | Provider id |

**Returns:** `{ success, provider, path, files:[{ name, key, path, size, etag, modified }], folders[] }`

---

## get_file_info
HEAD metadata for a single object.

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `path` | string | ✅ | Object key |
| `provider` | string | ✅ | Provider id |

**Returns:** `{ success, file: { path, provider, size, contentType, lastModified, etag } }`

---

## organize_files
Plan (and optionally execute) moving files into subfolders within **one** provider.

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `strategy` | string | ✅ | `by_type` \| `by_date` \| `by_size` |
| `provider` | string | ✅ | Provider id |
| `path` | string | – | Base prefix (default root) |
| `execute` | boolean | – | `false` = preview plan; `true` = apply (copy+delete) |

- `by_type` → `<ext>/`, `by_date` → `YYYY-MM/`, `by_size` → `small|medium|large|huge/`.
- Preview returns `{ planned, preview:[{from,to}] }`. Execute caps at 200 moves and
  requires `enableAutoExecution`.

---

## delete_files
Delete specific files.

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `files` | array | ✅ | `[{ provider, path }]` |
| `confirm` | boolean | ✅ | Must be `true` |

**Returns:** `{ success, deleted, failed, results:[{ file, success, status }] }`

---

## move_files
Move/copy files. Same-provider uses server-side `x-amz-copy-source`; cross-provider streams
through the Worker (capped at 100 MB/object).

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `files` | array | ✅ | `[{ provider, path }]` |
| `destination` | string | ✅* | Destination folder/prefix |
| `targetProvider` | string | – | Different provider id (cross-provider) |
| `copy` | boolean | – | Copy instead of move (keep source) |

\* Provide `destination` and/or `targetProvider`. Requires `enableAutoExecution`.
**Returns:** `{ success, operation, moved, failed, results[] }`

---

## generate_insights
Data-driven recommendations.

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `analysisType` | string | ✅ | `duplicates` \| `large_files` \| `optimization` |
| `threshold` | number | – | Size (MB) for `large_files` |

`duplicates` reuses `find_duplicates`. **Returns:** `{ success, analysisType, insights[], data, duplicates? }`

---

## batch_operations
Select files by criteria, then act in bulk.

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `operation` | string | ✅ | `delete` \| `move` \| `links` \| `list` |
| `criteria` | object | ✅ | `{ provider?, path?, nameContains?, extension?, minSizeMB?, maxSizeMB? }` |
| `options` | object | – | `{ limit?, confirm?, destination?, targetProvider?, copy?, linkTypes?, shareExpiry? }` |

Dispatches to `delete_files` / `move_files` / `generate_links` or returns a `list`.

---

## generate_links
All link types for one or more files.

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `files` | array | ✅ | `[{ provider, path }]` |
| `linkTypes` | array | – | Any of `download`, `share`, `direct`, `streaming` (default: all) |
| `shareExpiry` | number | – | Presigned share expiry in seconds (default 3600) |

Uses the live request origin for CDN/streaming/download URLs.
**Returns:** `{ success, totalFiles, results:[{ file, provider, links:{ download, share, direct, streaming } }], summary }`

---

## find_duplicates
Detect duplicate files across providers.

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `minSize` | number | – | Minimum size (MB) to consider |
| `keepStrategy` | string | – | `first` (default) or `last` |

Grouping prefers **content hash** (ETag = MD5 for non-multipart objects); falls back to
`basename + size`. Scans up to 5 levels, capped at 20,000 files.
**Returns:** `{ success, duplicates:[{ name, path, provider, size, keepingCopy }], duplicateGroups[], totalDuplicates, totalGroups, potentialSavings, potentialSavingsFormatted, message }`
