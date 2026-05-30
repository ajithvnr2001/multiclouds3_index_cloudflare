// Zero-dependency tests for the Multi-Cloud S3 Index Worker (v7.0).
// Run with:  node --test
//
// These tests exercise the real default export's fetch() with mocked global
// `fetch` and `caches`, so no network, credentials, or build step are needed.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// --- Global polyfills/mocks (must be set BEFORE importing the worker) ---
globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };

// Swappable fetch handler so each test can define upstream behavior.
let fetchHandler = async () => new Response('', { status: 200 });
globalThis.fetch = (url, opts) => fetchHandler(url, opts);

const worker = (await import('../multiclouds3 v7.0.js')).default;

const HOST = 'https://x.dev';
const env = {
  AUTH_USERNAME: 'u',
  AUTH_PASSWORD: 'p',
  MCP_TOKEN: 'tok',
  WASABI_ACCESS_KEY_ID: 'AK',
  WASABI_SECRET_ACCESS_KEY: 'SK',
  WASABI_BUCKET_NAME: 'bucket',
  WASABI_REGION: 'us-east-1'
};
const basic = 'Basic ' + Buffer.from('u:p').toString('base64');
const ctx = { waitUntil() {} };

function req(path, init = {}) {
  return worker.fetch(new Request(HOST + path, init), env, ctx);
}
function mcp(body, headers = { Authorization: 'Bearer tok' }) {
  return req('/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
test('browse without credentials -> 401', async () => {
  const r = await req('/wasabi/');
  assert.equal(r.status, 401);
  assert.match(r.headers.get('WWW-Authenticate') || '', /Basic realm/);
});

test('browse with wrong password -> 401 (fail closed)', async () => {
  const r = await req('/wasabi/', { headers: { Authorization: 'Basic ' + Buffer.from('u:nope').toString('base64') } });
  assert.equal(r.status, 401);
});

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------
test('MCP rejects unauthorized', async () => {
  const r = await mcp({ jsonrpc: '2.0', id: 1, method: 'initialize' }, {});
  assert.equal(r.status, 401);
});

test('MCP initialize returns serverInfo', async () => {
  const j = await (await mcp({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })).json();
  assert.equal(j.result.serverInfo.name, 'multicloud-s3-mcp');
  assert.ok(j.result.capabilities.tools);
});

test('MCP tools/list returns 11 valid tools', async () => {
  const j = await (await mcp({ jsonrpc: '2.0', id: 2, method: 'tools/list' })).json();
  assert.equal(j.result.tools.length, 11);
  for (const t of j.result.tools) {
    assert.ok(t.name && t.description);
    assert.equal(t.inputSchema.type, 'object');
  }
  const sf = j.result.tools.find(t => t.name === 'search_files');
  assert.ok(sf.inputSchema.required.includes('query'));
});

test('MCP ping returns empty result', async () => {
  const j = await (await mcp({ jsonrpc: '2.0', id: 3, method: 'ping' })).json();
  assert.deepEqual(j.result, {});
});

test('MCP tools/call degrades gracefully without provider creds', async () => {
  // search_files with only wasabi creds: other providers error internally but are caught.
  const j = await (await mcp({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'search_files', arguments: { query: 'x' } } })).json();
  assert.equal(j.result.content[0].type, 'text');
});

test('MCP unknown method -> -32601', async () => {
  const j = await (await mcp({ jsonrpc: '2.0', id: 5, method: 'no/such' })).json();
  assert.equal(j.error.code, -32601);
});

test('MCP unknown tool -> -32602', async () => {
  const j = await (await mcp({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'nope', arguments: {} } })).json();
  assert.equal(j.error.code, -32602);
});

test('MCP notification -> 202 no body', async () => {
  const r = await mcp({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(r.status, 202);
});

test('MCP GET descriptor (no auth)', async () => {
  const j = await (await req('/mcp')).json();
  assert.equal(j.name, 'multicloud-s3-mcp');
  assert.equal(j.transport, 'streamable-http');
});

// ---------------------------------------------------------------------------
// Browse: pagination + key decoding + XSS escaping
// ---------------------------------------------------------------------------
test('browse paginates, decodes keys, and escapes XSS', async () => {
  let listCalls = 0;
  fetchHandler = async (url) => {
    const u = typeof url === 'string' ? url : url.url;
    if (!u.includes('list-type=2')) return new Response('nope', { status: 404 });
    listCalls++;
    if (!u.includes('continuation-token=')) {
      return new Response(`<?xml version="1.0"?><ListBucketResult>
        <IsTruncated>true</IsTruncated>
        <NextContinuationToken>tok+12/3abc==</NextContinuationToken>
        <CommonPrefixes><Prefix>folder%20one/</Prefix></CommonPrefixes>
        <Contents><Key>a%26b%20c%2Bd.mp4</Key><Size>1048576</Size><LastModified>2024-01-01T00:00:00.000Z</LastModified><ETag>&quot;abc&quot;</ETag></Contents>
        <Contents><Key>evil%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E.mp4</Key><Size>2048</Size><LastModified>2024-01-02T00:00:00.000Z</LastModified></Contents>
      </ListBucketResult>`, { status: 200 });
    }
    return new Response(`<?xml version="1.0"?><ListBucketResult>
      <IsTruncated>false</IsTruncated>
      <Contents><Key>page2file.txt</Key><Size>10</Size><LastModified>2024-01-03T00:00:00.000Z</LastModified></Contents>
    </ListBucketResult>`, { status: 200 });
  };

  const r = await req('/wasabi/', { headers: { Authorization: basic } });
  const html = await r.text();
  fetchHandler = async () => new Response('', { status: 200 }); // reset

  assert.equal(r.status, 200);
  assert.equal(listCalls, 2, 'should follow the continuation token');
  assert.ok(html.includes('page2file.txt'), 'page 2 results present');
  assert.ok(html.includes('a&amp;b c+d.mp4'), 'key decoded and HTML-escaped');
  assert.ok(html.includes('c+d.mp4'), 'literal + preserved (not turned into space)');
  assert.ok(html.includes('folder one'), 'folder prefix decoded');
  assert.ok(!html.includes('<img src=x onerror=alert(1)>'), 'no raw XSS tag injected');
  assert.ok(html.includes('&lt;img'), 'XSS filename escaped');
});

// ---------------------------------------------------------------------------
// Share links (no network; pure signing)
// ---------------------------------------------------------------------------
test('share returns a direct presigned link', async () => {
  const j = await (await req('/wasabi/videos/movie.mp4?share', { headers: { Authorization: basic } })).json();
  assert.equal(j.success, true);
  assert.equal(j.type, 'direct');
  assert.equal(j.expires_in_seconds, 604800);
  assert.match(j.url, /X-Amz-Signature=/);
});

test('share&cdn=true returns a CDN (Worker) link', async () => {
  const j = await (await req('/wasabi/videos/movie.mp4?share&cdn=true', { headers: { Authorization: basic } })).json();
  assert.equal(j.type, 'cdn');
  assert.ok(j.url.endsWith('/wasabi/videos/movie.mp4?stream'), 'CDN link keeps the provider prefix');
});

// ---------------------------------------------------------------------------
// AI chat without an API key -> graceful JSON error
// ---------------------------------------------------------------------------
test('aiChat without OPENROUTER_API_KEY -> JSON error, no stack leak', async () => {
  const r = await req('/?aiChat', { method: 'POST', headers: { Authorization: basic, 'Content-Type': 'application/json' }, body: JSON.stringify({ message: 'hi' }) });
  const j = await r.json();
  assert.equal(j.success, false);
  assert.ok(j.error);
  assert.equal(j.errorDetails, undefined, 'stack hidden when debug is off');
});

// ---------------------------------------------------------------------------
// CORS preflight does not pre-authorize cross-origin DELETE
// ---------------------------------------------------------------------------
test('OPTIONS does not advertise DELETE for normal paths', async () => {
  const r = await req('/wasabi/x', { method: 'OPTIONS', headers: { Origin: 'https://evil.test', 'Access-Control-Request-Method': 'DELETE' } });
  assert.equal(r.status, 204);
  assert.ok(!(r.headers.get('Access-Control-Allow-Methods') || '').includes('DELETE'));
});

test('OPTIONS for /mcp allows POST', async () => {
  const r = await req('/mcp', { method: 'OPTIONS' });
  assert.ok((r.headers.get('Access-Control-Allow-Methods') || '').includes('POST'));
});
