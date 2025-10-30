const CONFIG = {
  siteName: "Multi-Cloud S3 Index",
  siteIcon: "🌤️",
  theme: "dark",
  defaultPath: "",
  passwordProtected: true,
  authMode: "username", // "password" (old) or "username" (WebDAV-style with username+password)
  username: "username",
  password: "password",
  experimentalMkvSupport: true,
  routingStrategy: "path-based",
  pathRouting: {
    "impossible/": "impossiblecloud",
    "wasabi/": "wasabi",
    "r2/": "cloudflarer2",
    "oci/": "oraclecloud", // <-- ADDED
    default: "impossiblecloud"
  },
  providerPriority: ["impossiblecloud", "wasabi", "cloudflarer2", "oraclecloud"], // <-- ADDED
  defaultSort: { field: "name", direction: "asc" }, // <-- ADDED: Default sorting
  enableAIChat: true, // Enable AI Assistant powered by OpenRouter
  aiProvider: "openrouter", // Using OpenRouter instead of Cloudflare AI
  aiModel: "minimax/minimax-m2:free", // DeepSeek Chat v3.1 Free model
  enableAgenticAI: true, // Enable autonomous agent capabilities
  agentConfig: {
    maxIterations: 8, // Maximum tool-use iterations per conversation
    enableAutoExecution: true, // Allow agent to execute file operations automatically
    requireConfirmation: false, // Set true to require user confirmation before executing operations
    tools: [
      "search_files", // Search across all cloud providers
      "analyze_storage", // Analyze storage usage and patterns
      "list_directory", // List files in specific directory
      "get_file_info", // Get detailed file metadata
      "organize_files", // Suggest or execute file organization
      "delete_files", // Delete files (with safety checks)
      "move_files", // Move files between paths or providers
      "generate_insights", // Analyze and provide storage insights
      "batch_operations", // Execute batch file operations
      "generate_links", // Generate all types of links for files
      "find_duplicates" // Find duplicate files for deletion
    ]
  },
  availableThemes: {
    dark: {
      name: "🌙 Dark",
      background: "linear-gradient(135deg,#1a1a1a 0%,#2d2d2d 100%)",
      surface: "#252525",
      surfaceSecondary: "#1e1e1e",
      text: "#e0e0e0",
      textSecondary: "#888",
      accent: "#4d9fff",
      accentSecondary: "#333",
      border: "#333",
      success: "#28a745",
      error: "#dc3545",
      warning: "#fd7e14"
    },
    light: {
      name: "☀️ Light",
      background: "linear-gradient(135deg,#f5f7fa 0%,#c3cfe2 100%)",
      surface: "#ffffff",
      surfaceSecondary: "#f8f9fa",
      text: "#2c3e50",
      textSecondary: "#6c757d",
      accent: "#0066cc",
      accentSecondary: "#e9ecef",
      border: "#dee2e6",
      success: "#28a745",
      error: "#dc3545",
      warning: "#fd7e14"
    },
    blue: {
      name: "🌊 Blue",
      background: "linear-gradient(135deg,#667eea 0%,#764ba2 100%)",
      surface: "rgba(255,255,255,0.95)",
      surfaceSecondary: "rgba(255,255,255,0.9)",
      text: "#2c3e50",
      textSecondary: "#6c757d",
      accent: "#4a90e2",
      accentSecondary: "rgba(74,144,226,0.1)",
      border: "rgba(74,144,226,0.2)",
      success: "#28a745",
      error: "#dc3545",
      warning: "#fd7e14"
    },
    purple: {
      name: "💜 Purple",
      background: "linear-gradient(135deg,#a855f7 0%,#ec4899 100%)",
      surface: "rgba(255,255,255,0.95)",
      surfaceSecondary: "rgba(255,255,255,0.9)",
      text: "#2c3e50",
      textSecondary: "#6c757d",
      accent: "#a855f7",
      accentSecondary: "rgba(168,85,247,0.1)",
      border: "rgba(168,85,247,0.2)",
      success: "#28a745",
      error: "#dc3545",
      warning: "#fd7e14"
    },
    sunset: {
      name: "🌅 Sunset",
      background: "linear-gradient(135deg,#ff9a9e 0%,#fecfef 50%,#fecfef 100%)",
      surface: "rgba(255,255,255,0.95)",
      surfaceSecondary: "rgba(255,255,255,0.9)",
      text: "#2c3e50",
      textSecondary: "#6c757d",
      accent: "#ff6b9d",
      accentSecondary: "rgba(255,107,157,0.1)",
      border: "rgba(255,107,157,0.2)",
      success: "#28a745",
      error: "#dc3545",
      warning: "#fd7e14"
    },
    forest: {
      name: "🌲 Forest",
      background: "linear-gradient(135deg,#1e5a3d 0%,#2d8a5e 100%)",
      surface: "#2a6a4d",
      surfaceSecondary: "#1e5a3d",
      text: "#e0f0e9",
      textSecondary: "#a8d8c3",
      accent: "#4caf50",
      accentSecondary: "rgba(76, 175, 80, 0.1)",
      border: "#3d8b6d",
      success: "#8bc34a",
      error: "#f44336",
      warning: "#ffc107"
    }
  },
  enableGlobalSearch: true,
  searchCacheTime: 300,
};

const PROVIDERS = {
  impossiblecloud: {
    name: "ImpossibleCloud",
    icon: "☁️",
    description: "🇪🇺 European • Zero Egress Fees",
    endpoints: {
      "eu-central-2": "eu-central-2.storage.impossibleapi.net",
      "eu-west-1": "eu-west-1.storage.impossibleapi.net",
      "eu-west-2": "eu-west-2.storage.impossibleapi.net",
      "eu-east-1": "eu-east-1.storage.impossibleapi.net",
      "eu-north-1": "eu-north-1.storage.impossibleapi.net"
    },
    defaultRegion: "eu-central-2",
    addressingStyle: "virtual" // <-- ADDED for clarity
  },
  wasabi: {
    name: "Wasabi",
    icon: "🪣",
    description: "🌍 Global • Hot Cloud Storage",
    endpoints: {
      "us-east-1": "s3.wasabisys.com",
      "us-east-2": "s3.us-east-2.wasabisys.com",
      "us-west-1": "s3.us-west-1.wasabisys.com",
      "eu-central-1": "s3.eu-central-1.wasabisys.com",
      "eu-central-2": "s3.eu-central-2.wasabisys.com",
      "eu-west-1": "s3.eu-west-1.wasabisys.com",
      "eu-west-2": "s3.eu-west-2.wasabisys.com",
      "ap-northeast-1": "s3.ap-northeast-1.wasabisys.com",
      "ap-northeast-2": "s3.ap-northeast-2.wasabisys.com",
      "ap-southeast-1": "s3.ap-southeast-1.wasabisys.com",
      "ap-southeast-2": "s3.ap-southeast-2.wasabisys.com"
    },
    defaultRegion: "us-east-1",
    addressingStyle: "virtual" // <-- ADDED for clarity
  },
  cloudflarer2: {
    name: "Cloudflare R2",
    icon: "🔶",
    description: "🚀 Cloudflare • Zero Egress Fees",
    endpoints: {
      "auto": "ACCOUNT_ID.r2.cloudflarestorage.com"
    },
    defaultRegion: "auto",
    addressingStyle: "virtual" // <-- ADDED for clarity
  },
  oraclecloud: { // <-- NEW PROVIDER ADDED
    name: "Oracle Cloud",
    icon: "🔴",
    description: "OCI • S3-Compatible Storage",
    endpoints: {
      "ap-hyderabad-1": "compat.objectstorage.ap-hyderabad-1.oraclecloud.com",
      "us-ashburn-1": "compat.objectstorage.us-ashburn-1.oraclecloud.com",
      "eu-frankfurt-1": "compat.objectstorage.eu-frankfurt-1.oraclecloud.com",
      "uk-london-1": "compat.objectstorage.uk-london-1.oraclecloud.com"
    },
    defaultRegion: "ap-hyderabad-1",
    addressingStyle: "path" // <-- CRITICAL: OCI requires path-style
  }
};

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return handleOptions(request);
    }

    try {
      const url = new URL(request.url);
      const rawPath = decodeURIComponent(url.pathname).replace(/^\//, "");

      if (url.pathname === "/favicon.ico") {
        return serveFavicon();
      }

      if (CONFIG.passwordProtected && !await checkAuth(request)) {
        return new Response(getLoginPage(), {
          status: 401,
          headers: {
            "Content-Type": "text/html",
            "WWW-Authenticate": `Basic realm="${CONFIG.siteName}"`
          }
        });
      }

      if (url.searchParams.has("search")) {
        return await handleGlobalSearch(url.searchParams.get("search"), env, request);
      }

      if (url.searchParams.has('bulkExport')) {
        return await handleBulkExport(
          url.searchParams.get('bulkExport'),
          url.searchParams.get('files'),
          env,
          request
        );
      }

      if (url.searchParams.has('bulkDelete')) {
        return await handleBulkDelete(
          url.searchParams.get('files'),
          env,
          request
        );
      }

      if (url.searchParams.has('aiChat') && request.method === 'POST') {
        return await handleAIChat(request, env);
      }

      const { provider, cleanPath } = determineProviderAndCleanPath(rawPath);
      const providerConfig = getProviderConfig(env, provider);

      if (request.method === "DELETE") {
        return await handleDelete(providerConfig, cleanPath, request);
      }

      if (url.searchParams.has("share")) {
        return await handleShareLink(providerConfig, cleanPath, request);
      } else if (url.searchParams.has("download")) {
        return await handleDownload(providerConfig, cleanPath, request, ctx);
      } else if (url.searchParams.has("preview")) {
        return await handlePreview(providerConfig, cleanPath, rawPath, request, ctx);
      } else if (url.searchParams.has("stream")) {
        return await handleStream(providerConfig, cleanPath, request, ctx);
      } else {
        return await handleBrowse(providerConfig, cleanPath, rawPath, request);
      }
    } catch (error) {
      console.error("Multi-Cloud Error:", error.message);
      const errorResponse = new Response(getErrorPage(error.message || "Multi-Cloud Error"), {
        status: error.status || 500,
        headers: { "Content-Type": "text/html" }
      });
      addCorsHeaders(errorResponse.headers);
      return errorResponse;
    }
  }
};

// --- CORS & CORE HELPER FUNCTIONS ---

function handleOptions(request) {
  const headers = new Headers();
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS, DELETE");
  headers.set("Access-Control-Max-Age", "86400");
  const reqHeaders = request.headers.get("Access-Control-Request-Headers");
  if (reqHeaders) {
    headers.set("Access-Control-Allow-Headers", reqHeaders);
  } else {
    headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-amz-date, x-amz-content-sha256, range");
  }
  return new Response(null, { status: 204, headers });
}

function addCorsHeaders(headers) {
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Expose-Headers", "Content-Disposition, Content-Type, Content-Length, ETag, X-Provider, Content-Range");
  return headers;
}

function determineProviderAndCleanPath(path) {
  for (const [prefix, provider] of Object.entries(CONFIG.pathRouting)) {
    if (prefix !== "default" && path.startsWith(prefix)) {
      return { provider, cleanPath: path.slice(prefix.length) };
    }
  }
  return { provider: CONFIG.pathRouting.default, cleanPath: path };
}

function serveFavicon() {
  const faviconBase64 = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAACFElEQVQ4T2NkwA3+gwEYjIwMUsAABF9Q5NMjAfMgFZmKIMHzAxgj8U7bZEQ/ClWDCWoA/0G+ByVZnYMBpGcSDoQRSJkARgJzHgMsaaAzEg2zDMC6BSpkOu4VwM0LGFgAAYzKRQKCACJMJWdgQZqukC7LQHkguAEEagHEWVU7og7C4YwAiYQiK+RYYGZAEirEXVYtAFpCECJnQnoA9G+gEEb/AC18WfBhgVhPgDIbHgskB83GdCXYLhBlGLgJwHsAUE1IMhIiZGFpA7FBo6jLDBAzMDAwETGBZAYzLAFIhcLhUCGHRBAlIu0kbBpgDJ3BqAAYBmWTiLNNINajQwEcK2EyIG8Z2QFIgsgwGgQbIBQBZQGBG0ClBfCGJZAUGp4CN9YWBAADECIEA4VkpHiAAAAAElFTkSuQmCC";
  return new Response(Uint8Array.from(atob(faviconBase64), c => c.charCodeAt(0)), {
    status: 200,
    headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=604800" }
  });
}

async function checkAuth(request) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) return false;
  
  const [scheme, encoded] = authHeader.split(" ");
  if (scheme !== "Basic") return false;
  
  const decoded = atob(encoded);
  const [username, pwd] = decoded.split(":");
  
  // WebDAV-style authentication: username + password
  if (CONFIG.authMode === "username") {
    return username === CONFIG.username && pwd === CONFIG.password;
  }
  
  // Legacy mode: password only (any username works)
  return pwd === CONFIG.password;
}

function getProviderConfig(env, provider) {
  const providerInfo = PROVIDERS[provider];
  if (!providerInfo) {
    throw { message: `Unknown provider: ${provider}`, status: 400 };
  }
  const config = {
    provider: provider,
    name: providerInfo.name,
    icon: providerInfo.icon,
    description: providerInfo.description,
    addressingStyle: providerInfo.addressingStyle || "virtual" // <-- Default to virtual
  };

  if (provider === "impossiblecloud") {
    config.accessKey = env.IMPOSSIBLE_ACCESS_KEY_ID;
    config.secretKey = env.IMPOSSIBLE_SECRET_ACCESS_KEY;
    config.bucket = env.IMPOSSIBLE_BUCKET_NAME;
    config.region = env.IMPOSSIBLE_REGION || providerInfo.defaultRegion;

    // Validate required environment variables
    if (!config.accessKey || !config.secretKey || !config.bucket) {
      throw { message: `Missing required environment variables for ImpossibleCloud. Please set: IMPOSSIBLE_ACCESS_KEY_ID, IMPOSSIBLE_SECRET_ACCESS_KEY, IMPOSSIBLE_BUCKET_NAME`, status: 500 };
    }
  } else if (provider === "wasabi") {
    config.accessKey = env.WASABI_ACCESS_KEY_ID;
    config.secretKey = env.WASABI_SECRET_ACCESS_KEY;
    config.bucket = env.WASABI_BUCKET_NAME;
    config.region = env.WASABI_REGION || providerInfo.defaultRegion;
  } else if (provider === "cloudflarer2") {
    config.accessKey = env.R2_ACCESS_KEY_ID;
    config.secretKey = env.R2_SECRET_ACCESS_KEY;
    config.bucket = env.R2_BUCKET_NAME;
    config.region = env.R2_REGION || providerInfo.defaultRegion;
    config.accountId = env.R2_ACCOUNT_ID;
  } else if (provider === "oraclecloud") { // <-- NEW OCI CONFIG
    config.accessKey = env.OCI_ACCESS_KEY_ID;
    config.secretKey = env.OCI_SECRET_ACCESS_KEY;
    config.bucket = env.OCI_BUCKET_NAME;
    config.region = env.OCI_REGION || providerInfo.defaultRegion;
    config.namespace = env.OCI_NAMESPACE;
  }
  
  // Handle endpoint construction
  if (provider === "cloudflarer2") {
    if (!config.accountId) throw { message: `R2_ACCOUNT_ID environment variable not set for R2`, status: 500 };
    config.endpoint = providerInfo.endpoints[config.region].replace("ACCOUNT_ID", config.accountId);
  } else if (provider === "oraclecloud") { // <-- NEW OCI ENDPOINT
    if (!config.namespace) throw { message: `OCI_NAMESPACE environment variable not set for Oracle Cloud`, status: 500 };
    const regionEndpoint = providerInfo.endpoints[config.region] || providerInfo.endpoints[providerInfo.defaultRegion];
    config.endpoint = `${config.namespace}.${regionEndpoint}`;
  } else {
    config.endpoint = providerInfo.endpoints[config.region] || providerInfo.endpoints[providerInfo.defaultRegion];
  }
  
  if (!config.accessKey || !config.secretKey || !config.bucket || !config.endpoint) {
    throw {
      message: `Incomplete configuration for ${providerInfo.name}. Please check environment variables.`,
      status: 500,
    };
  }
  return config;
}

// --- AWSv4 SIGNING ---

function awsUriEncode(str, encodeSlash = true) {
  let encoded = encodeURIComponent(str).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  if (!encodeSlash) {
    encoded = encoded.replace(/%2F/g, "/");
  }
  return encoded;
}

function createCanonicalQueryString(params) {
  const sortedKeys = Object.keys(params).sort();
  return sortedKeys.map((key) => `${awsUriEncode(key)}=${awsUriEncode(params[key])}`).join("&");
}

async function signRequest(providerConfig, method, path, queryParams = {}, payload = "", rangeHeader = null) {
  const service = "s3";
  const now = new Date();
  const dateStamp = now.toISOString().replace(/[:\-]|\.\d{3}/g, "").slice(0, 8);
  const amzDate = now.toISOString().replace(/[:\-]|\.\d{3}/g, "").slice(0, 15) + "Z";
  
  const payloadHash = await sha256(payload);

  // --- MODIFIED for Path-Style (OCI) vs Virtual-Style ---
  let endpoint;
  let canonicalUri;
  const pathSegments = path.split("/").map((segment) => awsUriEncode(segment, true));

  if (providerConfig.addressingStyle === "path") {
    // Path-Style: https://{endpoint}/{bucket}/{key}
    endpoint = providerConfig.endpoint;
    const bucketName = providerConfig.bucket;
    // For listObjects, path is "", so canonicalUri is /bucket/
    // For file ops, path is "file.txt", so canonicalUri is /bucket/file.txt
    canonicalUri = path ? `/${bucketName}/${pathSegments.join("/")}` : `/${bucketName}/`;
  } else {
    // Virtual-Hosted-Style: https://{bucket}.{endpoint}/{key}
    endpoint = `${providerConfig.bucket}.${providerConfig.endpoint}`;
    canonicalUri = path ? "/" + pathSegments.join("/") : "/";
  }
  // --- END MODIFICATION ---

  const canonicalQueryString = createCanonicalQueryString(queryParams);
  const headersToSign = {
    host: endpoint,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
  };
  if (rangeHeader) {
    headersToSign["range"] = rangeHeader;
  }
  const sortedHeaderKeys = Object.keys(headersToSign).sort();
  const canonicalHeaders = sortedHeaderKeys.map(key => `${key}:${headersToSign[key]}\n`).join('');
  const signedHeaders = sortedHeaderKeys.join(';');
  const canonicalRequest = `${method}\n${canonicalUri}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const algorithm = "AWS4-HMAC-SHA256";
  const credentialScope = `${dateStamp}/${providerConfig.region}/${service}/aws4_request`;
  const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${await sha256(canonicalRequest)}`;
  const signingKey = await getSignatureKey(providerConfig.secretKey, dateStamp, providerConfig.region, service);
  const signature = await hmacSha256(signingKey, stringToSign);
  const authorizationHeader = `${algorithm} Credential=${providerConfig.accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  const urlParams = new URLSearchParams(queryParams);
  const urlString = `https://${endpoint}${canonicalUri}${urlParams.toString() ? "?" + urlParams.toString() : ""}`;
  const fetchHeaders = {
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
    Authorization: authorizationHeader,
  };
  if (rangeHeader) {
    fetchHeaders["range"] = rangeHeader;
  }
  return {
    url: urlString,
    headers: fetchHeaders,
  };
}

async function generatePresignedUrl(providerConfig, cleanPath, expiresInSeconds) {
    const service = "s3";
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:\-]|\.\d{3}/g, "").slice(0, 15) + "Z";
    const dateStamp = amzDate.slice(0, 8);
    const credentialScope = `${dateStamp}/${providerConfig.region}/${service}/aws4_request`;

    const queryParams = {
      "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
      "X-Amz-Credential": `${providerConfig.accessKey}/${credentialScope}`,
      "X-Amz-Date": amzDate,
      "X-Amz-Expires": expiresInSeconds,
      "X-Amz-SignedHeaders": "host",
    };

    const canonicalQueryString = createCanonicalQueryString(queryParams);

    // --- MODIFIED for Path-Style (OCI) vs Virtual-Style ---
    let endpoint;
    let canonicalUri;
    const encodedPath = cleanPath.split("/").map(s => awsUriEncode(s, true)).join("/");

    if (providerConfig.addressingStyle === "path") {
      // Path-Style: https://{endpoint}/{bucket}/{key}
      endpoint = providerConfig.endpoint;
      canonicalUri = `/${providerConfig.bucket}/${encodedPath}`;
    } else {
      // Virtual-Hosted-Style: https://{bucket}.{endpoint}/{key}
      endpoint = `${providerConfig.bucket}.${providerConfig.endpoint}`;
      canonicalUri = `/${encodedPath}`;
    }
    // --- END MODIFICATION ---

    const canonicalHeaders = `host:${endpoint}\n`;
    const signedHeaders = "host";
    const payloadHash = "UNSIGNED-PAYLOAD";
    
    const canonicalRequest = `GET\n${canonicalUri}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

    const algorithm = "AWS4-HMAC-SHA256";
    const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${await sha256(canonicalRequest)}`;

    const signingKey = await getSignatureKey(providerConfig.secretKey, dateStamp, providerConfig.region, service);
    const signature = await hmacSha256(signingKey, stringToSign);

    return `https://${endpoint}${canonicalUri}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
}

// --- CRYPTO HELPERS ---

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256(key, message) {
  const encoder = new TextEncoder();
  const keyData = typeof key === "string" ? encoder.encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(message));
  const hashArray = Array.from(new Uint8Array(signature));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function getSignatureKey(key, dateStamp, regionName, serviceName) {
  const encoder = new TextEncoder();
  const kDate = await hmacSha256Raw(encoder.encode("AWS4" + key), dateStamp);
  const kRegion = await hmacSha256Raw(kDate, regionName);
  const kService = await hmacSha256Raw(kRegion, serviceName);
  const kSigning = await hmacSha256Raw(kService, "aws4_request");
  return kSigning;
}

async function hmacSha256Raw(key, message) {
  const encoder = new TextEncoder();
  const keyData = typeof key === "string" ? encoder.encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(message));
  return new Uint8Array(signature);
}

// --- S3 API HELPERS ---

async function listObjects(providerConfig, prefix = "", delimiter = "/") {
  const queryParams = { "list-type": "2", delimiter, "max-keys": "1000" };
  if (prefix) {
    queryParams.prefix = prefix;
  }
  const { url, headers } = await signRequest(providerConfig, "GET", "", queryParams);
  const response = await fetch(url, { headers });
  if (!response.ok) {
    const errorText = await response.text();
    throw { message: `Failed to list objects from ${providerConfig.name} (S3 Status: ${response.status}): ${errorText}`, status: response.status };
  }
  const xmlText = await response.text();
  return parseListBucketResult(xmlText, providerConfig);
}

function parseListBucketResult(xml, providerConfig) {
  const folders = [];
  const files = [];
  const routingPrefix = Object.keys(CONFIG.pathRouting).find(k => CONFIG.pathRouting[k] === providerConfig.provider) || "";
  const prefixMatches = xml.matchAll(/<CommonPrefixes>.*?<Prefix>(.*?)<\/Prefix>.*?<\/CommonPrefixes>/gs);
  for (const match of prefixMatches) {
    const prefix = match[1];
    const name = prefix.replace(/\/$/, "").split("/").pop();
    const fullLinkPrefix = routingPrefix + prefix;
    folders.push({ name, prefix: fullLinkPrefix, provider: providerConfig.provider });
  }
  const contentMatches = xml.matchAll(/<Contents>(.*?)<\/Contents>/gs);
  for (const match of contentMatches) {
    const content = match[1];
    const keyMatch = content.match(/<Key>(.*?)<\/Key>/);
    const sizeMatch = content.match(/<Size>(.*?)<\/Size>/);
    const modifiedMatch = content.match(/<LastModified>(.*?)<\/LastModified>/);
    if (keyMatch) {
      const key = keyMatch[1];
      if (key.endsWith("/")) continue;
      const name = key.split("/").pop();
      const size = sizeMatch ? parseInt(sizeMatch[1]) : 0;
      const lastModified = modifiedMatch ? modifiedMatch[1] : "";
      files.push({ name, key: routingPrefix + key, size, lastModified, provider: providerConfig.provider, providerName: providerConfig.name, providerIcon: providerConfig.icon });
    }
  }
  return { folders, files };
}

// --- ROUTE HANDLERS ---

async function handleDelete(providerConfig, cleanPath, request) {
  if (!cleanPath) {
    throw { message: "No file path provided for deletion", status: 400 };
  }

  try {
    const { url, headers } = await signRequest(providerConfig, "DELETE", cleanPath);
    
    const response = await fetch(url, {
      method: "DELETE",
      headers: headers
    });

    if (response.status === 204) {
      const jsonResponse = { success: true, message: "File deleted successfully" };
      const respHeaders = new Headers({ "Content-Type": "application/json" });
      addCorsHeaders(respHeaders);
      return new Response(JSON.stringify(jsonResponse), { headers: respHeaders, status: 200 });
    } else {
      const errorText = await response.text();
      throw { message: `Delete failed from ${providerConfig.name} (S3 Status: ${response.status}): ${errorText}`, status: response.status };
    }
  } catch (error) {
    const jsonResponse = { success: false, error: error.message || "Failed to delete file" };
    const respHeaders = new Headers({ "Content-Type": "application/json" });
    addCorsHeaders(respHeaders);
    return new Response(JSON.stringify(jsonResponse), { headers: respHeaders, status: error.status || 500 });
  }
}

async function handleShareLink(providerConfig, cleanPath, request) {
  try {
    const url = new URL(request.url);
    const useCDN = url.searchParams.get('cdn') === 'true';
    
    // CDN Link (Worker URL - cached, fast for repeated access)
    if (useCDN) {
      const baseUrl = url.origin;
      const cdnUrl = `${baseUrl}/${cleanPath}?stream`;
      
      const response = {
        success: true,
        url: cdnUrl,
        type: "cdn",
        expires_in_seconds: null,
        note: "⚡ CDN-Accelerated - Fast for repeated viewing"
      };
      
      // ✅ IMPROVEMENT #3: Cloudflare auto-compresses JSON/text responses
      const headers = new Headers({ "Content-Type": "application/json" });
      addCorsHeaders(headers);
      return new Response(JSON.stringify(response), { headers });
    }
    
    // Direct S3 Link (Original behavior)
    // Check if the provider is Oracle Cloud and generate a public URL
    if (providerConfig.provider === "oraclecloud") {
      if (!providerConfig.namespace || !providerConfig.region || !providerConfig.bucket) {
        throw new Error("Incomplete Oracle Cloud configuration for public URL. Missing namespace, region, or bucket.");
      }
      
      // URL-encode each part of the path, but keep the slashes
      const encodedName = cleanPath.split("/").map(s => awsUriEncode(s, true)).join("/");
      const publicUrl = `https://objectstorage.${providerConfig.region}.oraclecloud.com/n/${providerConfig.namespace}/b/${providerConfig.bucket}/o/${encodedName}`;
      
      const response = {
        success: true,
        url: publicUrl,
        type: "direct",
        expires_in_seconds: null,
        note: "🔗 Direct S3 - Best compatibility"
      };
      
      const headers = new Headers({ "Content-Type": "application/json" });
      addCorsHeaders(headers);
      return new Response(JSON.stringify(response), { headers });
    }

    // Default behavior for all other providers (generate presigned URL)
    const expiration = 604800; // 7 days
    const presignedUrl = await generatePresignedUrl(providerConfig, cleanPath, expiration);
    
    const response = {
      success: true,
      url: presignedUrl,
      type: "direct",
      expires_in_seconds: expiration,
      note: "🔗 Direct S3 - Best compatibility"
    };
    
    const headers = new Headers({ "Content-Type": "application/json" });
    addCorsHeaders(headers);
    
    return new Response(JSON.stringify(response), { headers });
    
  } catch (error) {
    const response = { success: false, error: error.message };
    const headers = new Headers({ "Content-Type": "application/json" });
    addCorsHeaders(headers);
    
    return new Response(JSON.stringify(response), { status: 500, headers });
  }
}

async function handleBulkExport(exportType, filesParam, env, request) {
  try {
    if (!filesParam) {
      throw new Error('No files provided for bulk export');
    }

    const fileEntries = filesParam.split(',').map(entry => {
      const [provider, ...pathParts] = entry.split(':');
      return { provider, path: pathParts.join(':') };
    });

    const linkPromises = fileEntries.map(async (fileEntry) => {
      try {
        const providerConfig = getProviderConfig(env, fileEntry.provider);
        
        // The path from frontend already includes routing prefix (e.g., "impossible/path/file.mp4")
        // We need to strip it to get the clean S3 path
        const fullPath = fileEntry.path;
        const routingPrefix = Object.keys(CONFIG.pathRouting).find(k => CONFIG.pathRouting[k] === providerConfig.provider);
        
        let cleanPath;
        if (routingPrefix && routingPrefix !== 'default' && fullPath.startsWith(routingPrefix)) {
          cleanPath = fullPath.substring(routingPrefix.length);
        } else {
          cleanPath = fullPath;
        }
        
        const fileName = cleanPath.split('/').pop();
        const baseUrl = new URL(request.url).origin;
        
        // CDN URL uses the full path with routing prefix
        const cdnUrl = `${baseUrl}/${fullPath}?stream`;

        // Generate direct S3 URL using clean path (without routing prefix)
        let directUrl;
        if (providerConfig.provider === "oraclecloud") {
          const encodedName = cleanPath.split("/").map(s => awsUriEncode(s, true)).join("/");
          directUrl = `https://objectstorage.${providerConfig.region}.oraclecloud.com/n/${providerConfig.namespace}/b/${providerConfig.bucket}/o/${encodedName}`;
        } else {
          const expiration = 604800; // 7 days
          directUrl = await generatePresignedUrl(providerConfig, cleanPath, expiration);
        }

        // Generate download URL
        const downloadUrl = `${baseUrl}/${fullPath}?download`;

        return {
          success: true,
          fileName: fileName,
          path: cleanPath,
          provider: providerConfig.name,
          providerIcon: providerConfig.icon,
          cdnUrl: cdnUrl,
          directUrl: directUrl,
          downloadUrl: downloadUrl
        };
      } catch (error) {
        return {
          success: false,
          fileName: fileEntry.path.split('/').pop(),
          path: fileEntry.path,
          provider: fileEntry.provider,
          error: error.message
        };
      }
    });

    const links = await Promise.all(linkPromises);

    let content, contentType;

    if (exportType === 'json') {
      content = JSON.stringify(links, null, 2);
      contentType = 'application/json';
    } else if (exportType === 'markdown') {
      content = '# Exported File Links\n\n';
      content += 'Generated: ' + new Date().toISOString() + '\n\n';
      links.forEach(link => {
        if (link.success) {
          content += '## ' + link.fileName + '\n';
          content += '- **Provider:** ' + link.providerIcon + ' ' + link.provider + '\n';
          content += '- **CDN Link:** ' + link.cdnUrl + '\n';
          content += '- **Direct Link:** ' + link.directUrl + '\n';
          content += '- **Download Link:** ' + link.downloadUrl + '\n\n';
        } else {
          content += '## ' + link.fileName + ' ❌\n';
          content += '- **Error:** ' + link.error + '\n\n';
        }
      });
      contentType = 'text/markdown';
    } else if (exportType === 'cdn') {
      content = '========================================\n';
      content += '  CDN LINKS (Worker-Accelerated)\n';
      content += '========================================\n';
      content += 'Generated: ' + new Date().toLocaleString() + '\n';
      content += 'Total Files: ' + links.filter(l => l.success).length + '\n';
      content += '========================================\n\n';
      links.filter(l => l.success).forEach((link, index) => {
        content += (index + 1) + '. ' + link.fileName + '\n';
        content += '   ' + link.cdnUrl + '\n\n';
      });
      contentType = 'text/plain';
    } else if (exportType === 'direct') {
      content = '========================================\n';
      content += '  DIRECT S3 LINKS (Presigned URLs)\n';
      content += '========================================\n';
      content += 'Generated: ' + new Date().toLocaleString() + '\n';
      content += 'Total Files: ' + links.filter(l => l.success).length + '\n';
      content += 'Expires: 7 days from generation\n';
      content += '========================================\n\n';
      links.filter(l => l.success).forEach((link, index) => {
        content += (index + 1) + '. ' + link.fileName + '\n';
        content += '   ' + link.directUrl + '\n\n';
      });
      contentType = 'text/plain';
    } else if (exportType === 'download') {
      content = '========================================\n';
      content += '  DOWNLOAD LINKS (Force Download)\n';
      content += '========================================\n';
      content += 'Generated: ' + new Date().toLocaleString() + '\n';
      content += 'Total Files: ' + links.filter(l => l.success).length + '\n';
      content += '========================================\n\n';
      links.filter(l => l.success).forEach((link, index) => {
        content += (index + 1) + '. ' + link.fileName + '\n';
        content += '   ' + link.downloadUrl + '\n\n';
      });
      contentType = 'text/plain';
    } else {
      content = '========================================\n';
      content += '  MULTI-CLOUD FILE LINKS EXPORT\n';
      content += '========================================\n';
      content += 'Generated: ' + new Date().toLocaleString() + '\n';
      content += 'Total Files: ' + links.filter(l => l.success).length + '\n';
      content += '========================================\n\n';
      
      content += '📦 CDN LINKS (Worker-Accelerated)\n';
      content += '─────────────────────────────────────\n';
      links.filter(l => l.success).forEach((link, index) => {
        content += (index + 1) + '. ' + link.fileName + '\n';
        content += '   ' + link.cdnUrl + '\n\n';
      });
      
      content += '\n🔗 DIRECT S3 LINKS (Presigned URLs - 7 Day Expiry)\n';
      content += '─────────────────────────────────────\n';
      links.filter(l => l.success).forEach((link, index) => {
        content += (index + 1) + '. ' + link.fileName + '\n';
        content += '   ' + link.directUrl + '\n\n';
      });
      
      content += '\n⬇️ DOWNLOAD LINKS (Force Download)\n';
      content += '─────────────────────────────────────\n';
      links.filter(l => l.success).forEach((link, index) => {
        content += (index + 1) + '. ' + link.fileName + '\n';
        content += '   ' + link.downloadUrl + '\n\n';
      });
      contentType = 'text/plain';
    }

    const headers = new Headers({ 'Content-Type': contentType });
    addCorsHeaders(headers);
    return new Response(content, { headers });

  } catch (error) {
    const response = { success: false, error: error.message };
    const headers = new Headers({ 'Content-Type': 'application/json' });
    addCorsHeaders(headers);
    return new Response(JSON.stringify(response), { status: 500, headers });
  }
}

async function handleBulkDelete(filesParam, env, request) {
  try {
    if (!filesParam) {
      throw new Error('No files provided for bulk delete');
    }

    const fileEntries = filesParam.split(',').map(entry => {
      const [provider, ...pathParts] = entry.split(':');
      return { provider, path: pathParts.join(':') };
    });

    const deletePromises = fileEntries.map(async (fileEntry) => {
      try {
        const providerConfig = getProviderConfig(env, fileEntry.provider);
        
        // The path from frontend already includes routing prefix
        const fullPath = fileEntry.path;
        const routingPrefix = Object.keys(CONFIG.pathRouting).find(k => CONFIG.pathRouting[k] === providerConfig.provider);
        
        let cleanPath;
        if (routingPrefix && routingPrefix !== 'default' && fullPath.startsWith(routingPrefix)) {
          cleanPath = fullPath.substring(routingPrefix.length);
        } else {
          cleanPath = fullPath;
        }
        
        const fileName = cleanPath.split('/').pop();

        // Delete the file from S3
        const { url, headers } = await signRequest(providerConfig, "DELETE", cleanPath);
        const response = await fetch(url, {
          method: "DELETE",
          headers: headers
        });

        if (response.status === 204) {
          return {
            success: true,
            fileName: fileName,
            path: cleanPath,
            provider: providerConfig.name,
            providerIcon: providerConfig.icon,
            message: 'Deleted successfully'
          };
        } else {
          const errorText = await response.text();
          throw new Error(`Delete failed (Status: ${response.status}): ${errorText}`);
        }
      } catch (error) {
        return {
          success: false,
          fileName: fileEntry.path.split('/').pop(),
          path: fileEntry.path,
          provider: fileEntry.provider,
          error: error.message
        };
      }
    });

    const results = await Promise.all(deletePromises);
    
    const successCount = results.filter(r => r.success).length;
    const failCount = results.filter(r => !r.success).length;

    const response = {
      success: true,
      total: results.length,
      deleted: successCount,
      failed: failCount,
      results: results
    };

    const headers = new Headers({ 'Content-Type': 'application/json' });
    addCorsHeaders(headers);
    return new Response(JSON.stringify(response), { headers });

  } catch (error) {
    const response = { success: false, error: error.message };
    const headers = new Headers({ 'Content-Type': 'application/json' });
    addCorsHeaders(headers);
    return new Response(JSON.stringify(response), { status: 500, headers });
  }
}

// ============================================================================
// AGENTIC AI SYSTEM - Tools and Functions
// ============================================================================

const AGENT_TOOLS = {
  search_files: {
    name: "search_files",
    description: "Search for files across all cloud providers or specific provider. Returns matching files with metadata.",
    parameters: {
      query: { type: "string", description: "Search query (file name pattern)", required: true },
      provider: { type: "string", description: "Specific provider to search (optional): impossiblecloud, wasabi, cloudflarer2, oraclecloud", required: false },
      fileType: { type: "string", description: "Filter by file extension (e.g., 'mp4', 'pdf')", required: false }
    }
  },
  
  analyze_storage: {
    name: "analyze_storage",
    description: "Analyze storage usage across providers. Returns total size, file counts, largest files, and usage patterns.",
    parameters: {
      provider: { type: "string", description: "Specific provider or 'all' for all providers", required: false },
      depth: { type: "number", description: "Directory depth to analyze (1-3)", required: false }
    }
  },
  
  list_directory: {
    name: "list_directory",
    description: "List files and folders in a specific directory path.",
    parameters: {
      path: { type: "string", description: "Directory path to list", required: true },
      provider: { type: "string", description: "Cloud provider name", required: true }
    }
  },
  
  get_file_info: {
    name: "get_file_info",
    description: "Get detailed metadata for a specific file.",
    parameters: {
      path: { type: "string", description: "Full file path", required: true },
      provider: { type: "string", description: "Cloud provider name", required: true }
    }
  },
  
  organize_files: {
    name: "organize_files",
    description: "Suggest or execute file organization based on patterns (by type, date, size).",
    parameters: {
      strategy: { type: "string", description: "Organization strategy: by_type, by_date, by_size, custom", required: true },
      path: { type: "string", description: "Base path to organize", required: false },
      execute: { type: "boolean", description: "Whether to execute (true) or just suggest (false)", required: false }
    }
  },
  
  delete_files: {
    name: "delete_files",
    description: "Delete specific files. Use with caution. Requires file paths array.",
    parameters: {
      files: { type: "array", description: "Array of {provider, path} objects to delete", required: true },
      confirm: { type: "boolean", description: "Safety confirmation", required: true }
    }
  },
  
  move_files: {
    name: "move_files",
    description: "Move or copy files to new location within same or different provider.",
    parameters: {
      files: { type: "array", description: "Array of {provider, path} objects to move", required: true },
      destination: { type: "string", description: "Destination path", required: true },
      targetProvider: { type: "string", description: "Target provider (if different)", required: false },
      copy: { type: "boolean", description: "Copy instead of move", required: false }
    }
  },
  
  generate_insights: {
    name: "generate_insights",
    description: "Generate insights about storage: duplicates, large files, old files, optimization opportunities.",
    parameters: {
      analysisType: { type: "string", description: "Type: duplicates, large_files, old_files, optimization", required: true },
      threshold: { type: "number", description: "Threshold for analysis (size in MB or days old)", required: false }
    }
  },
  
  batch_operations: {
    name: "batch_operations",
    description: "Execute batch operations on multiple files matching criteria.",
    parameters: {
      operation: { type: "string", description: "Operation: delete, move, export, tag", required: true },
      criteria: { type: "object", description: "Criteria for file selection", required: true },
      options: { type: "object", description: "Operation-specific options", required: false }
    }
  },
  
  generate_links: {
    name: "generate_links",
    description: "Generate all types of links (download, share, direct access, streaming) for single or multiple files.",
    parameters: {
      files: { type: "array", description: "Array of {provider, path} objects to generate links for", required: true },
      linkTypes: { type: "array", description: "Types of links to generate: download, share, direct, streaming (default: all)", required: false },
      shareExpiry: { type: "number", description: "Share link expiry time in seconds (default: 3600)", required: false }
    }
  },
  
  find_duplicates: {
    name: "find_duplicates",
    description: "Find duplicate files based on name and size. Returns list of duplicates ready for deletion.",
    parameters: {
      minSize: { type: "number", description: "Minimum file size in MB to consider (optional)", required: false },
      keepStrategy: { type: "string", description: "Which copy to keep: first, last, specific_provider (default: first)", required: false }
    }
  }
};

// Execute agent tool calls
async function executeAgentTool(toolName, parameters, env) {
  console.log(`[Agent] Executing tool: ${toolName}`, parameters);
  
  try {
    switch (toolName) {
      case "search_files":
        return await agentSearchFiles(parameters, env);
      
      case "analyze_storage":
        return await agentAnalyzeStorage(parameters, env);
      
      case "list_directory":
        return await agentListDirectory(parameters, env);
      
      case "get_file_info":
        return await agentGetFileInfo(parameters, env);
      
      case "organize_files":
        return await agentOrganizeFiles(parameters, env);
      
      case "delete_files":
        return await agentDeleteFiles(parameters, env);
      
      case "move_files":
        return await agentMoveFiles(parameters, env);
      
      case "generate_insights":
        return await agentGenerateInsights(parameters, env);
      
      case "batch_operations":
        return await agentBatchOperations(parameters, env);
      
      case "generate_links":
        return await agentGenerateLinks(parameters, env);
      
      case "find_duplicates":
        return await agentFindDuplicates(parameters, env);
      
      default:
        return { error: `Unknown tool: ${toolName}` };
    }
  } catch (error) {
    console.error(`[Agent] Tool execution error:`, error);
    return { error: error.message || String(error) };
  }
}

// Tool Implementation: Search Files
async function agentSearchFiles(params, env) {
  const { query, provider, fileType } = params;
  const providers = provider ? [provider] : CONFIG.providerPriority.filter(p => p !== 'default');
  
  let allResults = [];
  
  for (const prov of providers) {
    try {
      const providerConfig = getProviderConfig(env, prov);
      const files = await recursiveSearchFiles(providerConfig, query, fileType);
      allResults = allResults.concat(files.map(f => ({ ...f, provider: prov })));
    } catch (error) {
      console.error(`[Agent] Search error in ${prov}:`, error);
    }
  }
  
  return {
    success: true,
    totalFiles: allResults.length,
    files: allResults.slice(0, 50), // Limit to 50 results
    query: query
  };
}

// Tool Implementation: Analyze Storage
async function agentAnalyzeStorage(params, env) {
  const { provider = 'all', depth = 2 } = params;
  const providers = provider === 'all' ? CONFIG.providerPriority.filter(p => p !== 'default') : [provider];
  
  let analysis = {
    providers: {},
    totalFiles: 0,
    totalSize: 0,
    largestFiles: [],
    fileTypes: {}
  };
  
  for (const prov of providers) {
    try {
      const providerConfig = getProviderConfig(env, prov);
      const stats = await analyzeProviderStorage(providerConfig, depth);
      
      analysis.providers[prov] = stats;
      analysis.totalFiles += stats.fileCount;
      analysis.totalSize += stats.totalSize;
      analysis.largestFiles = [...analysis.largestFiles, ...stats.largestFiles]
        .sort((a, b) => b.size - a.size)
        .slice(0, 10);
        
      // Merge file types
      for (const [ext, count] of Object.entries(stats.fileTypes)) {
        analysis.fileTypes[ext] = (analysis.fileTypes[ext] || 0) + count;
      }
    } catch (error) {
      console.error(`[Agent] Analysis error in ${prov}:`, error);
      analysis.providers[prov] = { error: error.message };
    }
  }
  
  return {
    success: true,
    analysis: analysis,
    formatted: formatStorageAnalysis(analysis)
  };
}

// Tool Implementation: List Directory
async function agentListDirectory(params, env) {
  const { path, provider } = params;
  const providerConfig = getProviderConfig(env, provider);
  
  const result = await listObjects(providerConfig, path);
  
  return {
    success: true,
    provider: provider,
    path: path,
    files: result.files.map(f => ({
      name: f.key,
      size: f.size,
      modified: f.lastModified
    })),
    folders: result.folders
  };
}

// Tool Implementation: Get File Info
async function agentGetFileInfo(params, env) {
  const { path, provider } = params;
  const providerConfig = getProviderConfig(env, provider);
  
  // Use HEAD request to get metadata
  const { url, headers } = await signRequest(providerConfig, "HEAD", path);
  const response = await fetch(url, { method: "HEAD", headers });
  
  if (!response.ok) {
    return { success: false, error: `File not found: ${path}` };
  }
  
  return {
    success: true,
    file: {
      path: path,
      provider: provider,
      size: parseInt(response.headers.get('content-length') || 0),
      contentType: response.headers.get('content-type'),
      lastModified: response.headers.get('last-modified'),
      etag: response.headers.get('etag')
    }
  };
}

// Tool Implementation: Organize Files (suggestion mode)
async function agentOrganizeFiles(params, env) {
  const { strategy, path = '', execute = false } = params;
  
  // For now, return organizational suggestions
  // Full implementation would actually move files
  
  return {
    success: true,
    strategy: strategy,
    suggestions: [
      `Organize files by ${strategy} in path: ${path || 'root'}`,
      `This would create folders based on ${strategy} criteria`,
      execute ? 'Execution not yet implemented - preview only' : 'Set execute:true to apply changes'
    ],
    execute: execute
  };
}

// Tool Implementation: Delete Files
async function agentDeleteFiles(params, env) {
  const { files, confirm } = params;
  
  if (!confirm) {
    return { success: false, error: 'Deletion requires confirm:true for safety' };
  }
  
  if (!CONFIG.agentConfig.enableAutoExecution) {
    return { success: false, error: 'Auto-execution is disabled in config' };
  }
  
  const results = [];
  
  for (const file of files) {
    try {
      const providerConfig = getProviderConfig(env, file.provider);
      const { url, headers } = await signRequest(providerConfig, "DELETE", file.path);
      const response = await fetch(url, { method: "DELETE", headers });
      
      results.push({
        file: file.path,
        success: response.ok,
        status: response.status
      });
    } catch (error) {
      results.push({
        file: file.path,
        success: false,
        error: error.message
      });
    }
  }
  
  return {
    success: true,
    deleted: results.filter(r => r.success).length,
    failed: results.filter(r => !r.success).length,
    results: results
  };
}

// Tool Implementation: Move Files
async function agentMoveFiles(params, env) {
  const { files, destination, targetProvider, copy = false } = params;
  
  return {
    success: false,
    error: 'Move/copy operations not yet fully implemented',
    suggestion: 'Use download + upload workflow for cross-provider transfers'
  };
}

// Tool Implementation: Generate Insights
async function agentGenerateInsights(params, env) {
  const { analysisType, threshold } = params;
  
  // Get storage analysis first
  const storageData = await agentAnalyzeStorage({ provider: 'all', depth: 2 }, env);
  
  let insights = [];
  
  switch (analysisType) {
    case 'large_files':
      const sizeMB = threshold || 100;
      insights = storageData.analysis.largestFiles
        .filter(f => f.size > sizeMB * 1024 * 1024)
        .map(f => `Large file: ${f.name} (${formatSize(f.size)})`);
      break;
      
    case 'optimization':
      insights.push(`Total storage: ${formatSize(storageData.analysis.totalSize)}`);
      insights.push(`Total files: ${storageData.analysis.totalFiles}`);
      insights.push(`File types: ${Object.keys(storageData.analysis.fileTypes).length} different types`);
      
      // Find optimization opportunities
      const videoSize = Object.entries(storageData.analysis.fileTypes)
        .filter(([ext]) => ['mp4', 'mkv', 'avi'].includes(ext))
        .reduce((sum, [_, count]) => sum + count, 0);
      
      if (videoSize > 100) {
        insights.push(`Consider compressing ${videoSize} video files`);
      }
      break;
      
    case 'duplicates':
      // Find files with same name and size
      const filesByName = {};
      
      // Collect all files from analysis
      for (const [provider, providerData] of Object.entries(storageData.analysis.providers)) {
        if (providerData.error) continue;
        
        // We need to get files from storage again to check for duplicates
        const providerFiles = await agentSearchFiles({ query: '' }, env);
        
        for (const file of providerFiles.files || []) {
          const key = `${file.name}_${file.size}`;
          if (!filesByName[key]) {
            filesByName[key] = [];
          }
          filesByName[key].push({
            name: file.name,
            size: file.size,
            provider: file.provider
          });
        }
      }
      
      // Find duplicates (files with same name and size appearing multiple times)
      const duplicates = Object.entries(filesByName)
        .filter(([_, files]) => files.length > 1)
        .map(([_, files]) => ({
          name: files[0].name,
          size: files[0].size,
          count: files.length,
          locations: files.map(f => f.provider)
        }));
      
      if (duplicates.length > 0) {
        const totalDuplicateSize = duplicates.reduce((sum, d) => sum + (d.size * (d.count - 1)), 0);
        insights.push(`Found ${duplicates.length} potential duplicate file(s)`);
        insights.push(`Could save ${formatSize(totalDuplicateSize)} by removing duplicates`);
        
        // List duplicates
        duplicates.slice(0, 10).forEach(d => {
          insights.push(`- ${d.name} (${formatSize(d.size)}): ${d.count} copies in ${d.locations.join(', ')}`);
        });
      } else {
        insights.push('No duplicate files found (same name and size)');
      }
      
      // Return duplicate data for deletion
      return {
        success: true,
        analysisType: analysisType,
        insights: insights,
        data: storageData.analysis,
        duplicates: duplicates
      };
      break;
      
    default:
      insights.push(`Analysis type '${analysisType}' not fully implemented`);
  }
  
  return {
    success: true,
    analysisType: analysisType,
    insights: insights,
    data: storageData.analysis
  };
}

// Tool Implementation: Batch Operations
async function agentBatchOperations(params, env) {
  const { operation, criteria, options = {} } = params;
  
  return {
    success: false,
    error: 'Batch operations require careful implementation',
    suggestion: 'Use specific tools (delete_files, move_files) for safety'
  };
}

// Tool Implementation: Generate Links
async function agentGenerateLinks(params, env) {
  const { files, linkTypes = ['download', 'share', 'direct', 'streaming'], shareExpiry = 3600 } = params;
  
  if (!files || files.length === 0) {
    return { success: false, error: 'No files provided' };
  }
  
  const results = [];
  
  for (const file of files) {
    try {
      const providerConfig = getProviderConfig(env, file.provider);
      const cleanPath = file.path;
      
      // Get base URL from worker origin (we'll construct it)
      const workerOrigin = 'https://your-worker.workers.dev'; // This will be dynamic in actual request
      
      const fileLinks = {
        file: cleanPath,
        provider: file.provider,
        providerName: providerConfig.name,
        links: {}
      };
      
      // Generate Download Link
      if (linkTypes.includes('download')) {
        const routingPrefix = Object.keys(CONFIG.pathRouting).find(k => CONFIG.pathRouting[k] === file.provider) || '';
        fileLinks.links.download = {
          url: `${workerOrigin}/${routingPrefix}${cleanPath}?download`,
          type: 'download',
          description: '⬇️ Force download (triggers browser download)',
          expires: false
        };
      }
      
      // Generate Share Link (Presigned)
      if (linkTypes.includes('share')) {
        const presignedUrl = await generatePresignedUrl(providerConfig, cleanPath, shareExpiry);
        fileLinks.links.share = {
          url: presignedUrl,
          type: 'share',
          description: '🔗 Temporary share link (presigned, expires)',
          expires: true,
          expiresIn: shareExpiry,
          expiresInFormatted: formatExpiry(shareExpiry)
        };
      }
      
      // Generate Direct Access Link
      if (linkTypes.includes('direct')) {
        if (providerConfig.provider === 'oraclecloud') {
          // OCI public URL
          const encodedName = cleanPath.split("/").map(s => awsUriEncode(s, true)).join("/");
          const publicUrl = `https://objectstorage.${providerConfig.region}.oraclecloud.com/n/${providerConfig.namespace}/b/${providerConfig.bucket}/o/${encodedName}`;
          fileLinks.links.direct = {
            url: publicUrl,
            type: 'direct',
            description: '🌐 Direct S3 access (requires public bucket)',
            expires: false
          };
        } else {
          // Generate long-lived presigned URL (7 days)
          const longLivedUrl = await generatePresignedUrl(providerConfig, cleanPath, 604800);
          fileLinks.links.direct = {
            url: longLivedUrl,
            type: 'direct',
            description: '🌐 Direct S3 access (7-day presigned)',
            expires: true,
            expiresIn: 604800,
            expiresInFormatted: '7 days'
          };
        }
      }
      
      // Generate Streaming Link (for videos/audio)
      if (linkTypes.includes('streaming')) {
        const routingPrefix = Object.keys(CONFIG.pathRouting).find(k => CONFIG.pathRouting[k] === file.provider) || '';
        fileLinks.links.streaming = {
          url: `${workerOrigin}/${routingPrefix}${cleanPath}?stream`,
          type: 'streaming',
          description: '📺 CDN streaming (cached, supports range requests)',
          expires: false,
          supportsRangeRequests: true
        };
      }
      
      results.push(fileLinks);
      
    } catch (error) {
      results.push({
        file: file.path,
        provider: file.provider,
        error: error.message || String(error),
        success: false
      });
    }
  }
  
  return {
    success: true,
    totalFiles: files.length,
    results: results,
    summary: generateLinksSummary(results)
  };
}

// Helper: Format expiry time
function formatExpiry(seconds) {
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours`;
  return `${Math.floor(seconds / 86400)} days`;
}

// Helper: Generate links summary
function generateLinksSummary(results) {
  const successful = results.filter(r => !r.error).length;
  const failed = results.filter(r => r.error).length;
  
  let summary = `Generated links for ${successful} file(s)`;
  if (failed > 0) {
    summary += `, ${failed} failed`;
  }
  
  return summary;
}

// Tool Implementation: Find Duplicates
async function agentFindDuplicates(params, env) {
  const { minSize = 0, keepStrategy = 'first' } = params;
  const minSizeBytes = minSize * 1024 * 1024;
  
  console.log('[Agent] Finding duplicates...');
  
  // Get all files from all providers using listObjects directly
  const providers = CONFIG.providerPriority.filter(p => p !== 'default');
  const allFiles = [];
  
  for (const provider of providers) {
    try {
      const providerConfig = getProviderConfig(env, provider);
      console.log(`[Agent] Scanning ${provider}...`);
      
      // Use a helper to recursively get all files
      const files = await getAllFilesFromProvider(providerConfig, provider);
      allFiles.push(...files);
      
      console.log(`[Agent] Found ${files.length} files in ${provider}`);
    } catch (error) {
      console.error(`[Agent] Error scanning ${provider}:`, error);
    }
  }
  
  console.log(`[Agent] Total files found: ${allFiles.length}`);
  
  if (allFiles.length === 0) {
    return {
      success: true,
      duplicates: [],
      totalDuplicates: 0,
      potentialSavings: 0,
      message: 'No files found to check for duplicates'
    };
  }
  
  // Group files by basename and size (not full path, just filename)
  const fileGroups = {};
  
  for (const file of allFiles) {
    if (file.size < minSizeBytes) continue;
    
    // Get just the filename without path
    const basename = file.path.split('/').pop();
    const key = `${basename}|${file.size}`;
    
    if (!fileGroups[key]) {
      fileGroups[key] = [];
    }
    fileGroups[key].push(file);
  }
  
  // Find duplicates (groups with 2+ files)
  const duplicateGroups = Object.entries(fileGroups)
    .filter(([_, files]) => files.length > 1)
    .map(([_, files]) => files);
  
  console.log(`[Agent] Found ${duplicateGroups.length} duplicate groups`);
  
  if (duplicateGroups.length === 0) {
    return {
      success: true,
      duplicates: [],
      totalDuplicates: 0,
      potentialSavings: 0,
      message: 'No duplicate files found'
    };
  }
  
  // Prepare duplicates for deletion
  const duplicatesToDelete = [];
  let totalSavings = 0;
  
  for (const group of duplicateGroups) {
    // Sort by strategy
    let sorted = [...group];
    if (keepStrategy === 'last') {
      sorted.reverse();
    }
    
    // Keep first, mark rest for deletion
    const toKeep = sorted[0];
    const toDelete = sorted.slice(1);
    
    for (const dup of toDelete) {
      duplicatesToDelete.push({
        name: dup.path.split('/').pop(),
        path: dup.path,
        provider: dup.provider,
        size: dup.size,
        keepingCopy: `${toKeep.provider}/${toKeep.path}`
      });
      totalSavings += dup.size;
    }
  }
  
  console.log(`[Agent] ${duplicatesToDelete.length} files marked for deletion, saving ${formatSize(totalSavings)}`);
  
  return {
    success: true,
    duplicates: duplicatesToDelete,
    duplicateGroups: duplicateGroups.map(group => ({
      name: group[0].path.split('/').pop(),
      size: group[0].size,
      count: group.length,
      locations: group.map(f => ({provider: f.provider, path: f.path}))
    })),
    totalDuplicates: duplicatesToDelete.length,
    totalGroups: duplicateGroups.length,
    potentialSavings: totalSavings,
    potentialSavingsFormatted: formatSize(totalSavings),
    message: `Found ${duplicateGroups.length} duplicate file groups with ${duplicatesToDelete.length} files that can be deleted to save ${formatSize(totalSavings)}`
  };
}

// Helper: Get all files from a provider recursively
async function getAllFilesFromProvider(providerConfig, provider, prefix = '', maxDepth = 5, currentDepth = 0) {
  if (currentDepth >= maxDepth) {
    return [];
  }
  
  try {
    const result = await listObjects(providerConfig, prefix);
    let allFiles = [];
    
    // Add files at this level
    for (const file of result.files) {
      allFiles.push({
        name: file.key.split('/').pop(),
        path: file.key,
        size: file.size || 0,
        provider: provider,
        modified: file.lastModified
      });
    }
    
    // Recursively get files from subfolders
    for (const folder of result.folders) {
      const subFiles = await getAllFilesFromProvider(
        providerConfig, 
        provider, 
        folder.prefix, 
        maxDepth, 
        currentDepth + 1
      );
      allFiles = allFiles.concat(subFiles);
    }
    
    return allFiles;
  } catch (error) {
    console.error(`[Agent] Error listing objects at ${prefix}:`, error);
    return [];
  }
}

// Helper: Recursive file search
async function recursiveSearchFiles(providerConfig, query, fileType, prefix = '', maxDepth = 3, currentDepth = 0) {
  if (currentDepth >= maxDepth) return [];
  
  const result = await listObjects(providerConfig, prefix);
  let matches = [];
  
  // Search files at this level
  for (const file of result.files) {
    const fileName = file.key.toLowerCase();
    const queryLower = query.toLowerCase();
    
    const nameMatch = fileName.includes(queryLower);
    const typeMatch = !fileType || fileName.endsWith(`.${fileType.toLowerCase()}`);
    
    if (nameMatch && typeMatch) {
      matches.push({
        name: file.key,
        size: file.size,
        modified: file.lastModified
      });
    }
  }
  
  // Recursively search subfolders
  for (const folder of result.folders) {
    const subMatches = await recursiveSearchFiles(
      providerConfig, query, fileType, folder.prefix, maxDepth, currentDepth + 1
    );
    matches = matches.concat(subMatches);
  }
  
  return matches;
}

// Helper: Analyze provider storage
async function analyzeProviderStorage(providerConfig, depth = 2, prefix = '', currentDepth = 0) {
  if (currentDepth >= depth) {
    return { fileCount: 0, totalSize: 0, largestFiles: [], fileTypes: {} };
  }
  
  const result = await listObjects(providerConfig, prefix);
  
  let stats = {
    fileCount: result.files.length,
    totalSize: result.files.reduce((sum, f) => sum + (f.size || 0), 0),
    largestFiles: result.files.map(f => ({
      name: f.key,
      size: f.size || 0
    })).sort((a, b) => b.size - a.size).slice(0, 5),
    fileTypes: {}
  };
  
  // Count file types
  for (const file of result.files) {
    const ext = file.key.split('.').pop().toLowerCase();
    stats.fileTypes[ext] = (stats.fileTypes[ext] || 0) + 1;
  }
  
  // Recursively analyze subfolders
  for (const folder of result.folders) {
    const subStats = await analyzeProviderStorage(providerConfig, depth, folder.prefix, currentDepth + 1);
    stats.fileCount += subStats.fileCount;
    stats.totalSize += subStats.totalSize;
    stats.largestFiles = [...stats.largestFiles, ...subStats.largestFiles]
      .sort((a, b) => b.size - a.size)
      .slice(0, 5);
      
    for (const [ext, count] of Object.entries(subStats.fileTypes)) {
      stats.fileTypes[ext] = (stats.fileTypes[ext] || 0) + count;
    }
  }
  
  return stats;
}

// Helper: Format storage analysis
function formatStorageAnalysis(analysis) {
  return `
Storage Analysis:
- Total Files: ${analysis.totalFiles}
- Total Size: ${formatSize(analysis.totalSize)}
- Providers: ${Object.keys(analysis.providers).length}

Top File Types:
${Object.entries(analysis.fileTypes)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 5)
  .map(([ext, count]) => `  - .${ext}: ${count} files`)
  .join('\n')}

Largest Files:
${analysis.largestFiles
  .slice(0, 5)
  .map((f, i) => `  ${i + 1}. ${f.name} (${formatSize(f.size)})`)
  .join('\n')}
  `.trim();
}

// ============================================================================
// AGENTIC AI - Helper Functions
// ============================================================================

// Build system prompt with tool descriptions
function buildAgenticSystemPrompt(context) {
  const toolDescriptions = Object.values(AGENT_TOOLS).map(tool => {
    const params = Object.entries(tool.parameters)
      .map(([name, spec]) => `  - ${name} (${spec.type}${spec.required ? ', required' : ', optional'}): ${spec.description}`)
      .join('\n');
    
    return `**${tool.name}**: ${tool.description}\nParameters:\n${params}`;
  }).join('\n\n');

  return `You are an advanced autonomous AI agent managing a multi-cloud S3 storage system.

CAPABILITIES:
- Autonomous decision-making for file operations
- Multi-step reasoning and planning
- Tool use for storage operations across ImpossibleCloud, Wasabi, Cloudflare R2, and Oracle Cloud
- Intelligent analysis and insights

AVAILABLE TOOLS:
${toolDescriptions}

TOOL USAGE FORMAT:
To use a tool, respond with:
TOOL_CALL: tool_name
PARAMETERS: {"param1": "value1", "param2": value2}

You can use tools to:
1. Search and discover files
2. Analyze storage patterns and usage
3. Execute file operations (with user confirmation when needed)
4. Provide data-driven insights

Current Context: ${context ? JSON.stringify(context, null, 2) : 'No current files visible'}

GUIDELINES:
- Be proactive: if a user asks about files, search for them automatically
- Be analytical: provide insights with data to back them up
- Be safe: confirm before destructive operations unless auto-execution is enabled
- Be helpful: suggest optimizations and improvements
- Be efficient: use tools to gather information rather than guessing
- IMPORTANT: After using tools and getting results, provide your final answer WITHOUT calling more tools
- When you have all the information needed, respond naturally to the user without TOOL_CALL

HOW TO RESPOND:
1. If you need information: Use TOOL_CALL to get it
2. If you have tool results: Respond naturally WITHOUT TOOL_CALL
3. If user confirms action: Use appropriate tool (delete_files, etc) with confirm:true

Respond naturally but use tools when appropriate. After tool execution, you'll receive results to summarize for the user.`;
}

// Extract AI response from various formats
function extractAIResponse(aiResponse) {
  if (typeof aiResponse === 'string') {
    return aiResponse;
  }
  
  if (aiResponse.response) return aiResponse.response;
  if (aiResponse.result) return aiResponse.result;
  if (aiResponse.content) return aiResponse.content;
  if (aiResponse.choices && aiResponse.choices[0]?.message?.content) {
    return aiResponse.choices[0].message.content;
  }
  if (aiResponse.choices && aiResponse.choices[0]?.text) {
    return aiResponse.choices[0].text;
  }
  
  return JSON.stringify(aiResponse);
}

// Parse tool requests from AI response
function parseToolRequest(responseText) {
  // Look for TOOL_CALL pattern
  const toolCallMatch = responseText.match(/TOOL_CALL:\s*(\w+)/i);
  
  if (toolCallMatch) {
    const toolName = toolCallMatch[1].toLowerCase();
    let parameters = {};
    
    // Try to find PARAMETERS with nested JSON support
    const paramStartIndex = responseText.indexOf('PARAMETERS:');
    if (paramStartIndex !== -1) {
      const jsonStart = responseText.indexOf('{', paramStartIndex);
      if (jsonStart !== -1) {
        // Extract JSON by matching braces
        let braceCount = 0;
        let jsonEnd = jsonStart;
        for (let i = jsonStart; i < responseText.length; i++) {
          if (responseText[i] === '{') braceCount++;
          if (responseText[i] === '}') braceCount--;
          if (braceCount === 0) {
            jsonEnd = i + 1;
            break;
          }
        }
        
        try {
          const jsonStr = responseText.substring(jsonStart, jsonEnd);
          parameters = JSON.parse(jsonStr);
        } catch (e) {
          console.error('[Agent] Failed to parse parameters:', e);
          console.error('[Agent] JSON string was:', responseText.substring(jsonStart, jsonEnd));
        }
      }
    }
    
    // Validate tool exists
    if (AGENT_TOOLS[toolName]) {
      return {
        tool: toolName,
        parameters: parameters
      };
    }
  }
  
  // Alternative: Look for JSON function call format
  try {
    const jsonMatch = responseText.match(/\{[\s\S]*"function"[\s\S]*"parameters"[\s\S]*\}/);
    if (jsonMatch) {
      const funcCall = JSON.parse(jsonMatch[0]);
      if (funcCall.function && AGENT_TOOLS[funcCall.function]) {
        return {
          tool: funcCall.function,
          parameters: funcCall.parameters || {}
        };
      }
    }
  } catch (e) {
    // Not a function call format
  }
  
  return null;
}

// ============================================================================
// AGENTIC AI CHAT HANDLER with Tool Use & Multi-Step Reasoning
// ============================================================================

async function handleAIChat(request, env) {
  try {
    if (!CONFIG.enableAIChat) {
      throw new Error('AI Chat is disabled in configuration');
    }

    const body = await request.json();
    const { message, context, conversationHistory = [] } = body;

    if (!message) {
      throw new Error('No message provided');
    }

    // Check if OpenRouter API key is available
    if (!env.OPENROUTER_API_KEY) {
      throw new Error('OPENROUTER_API_KEY not configured. Please add your OpenRouter API key to environment variables.');
    }

    console.log('[Agent] Processing request:', message);

    // Build enhanced system prompt with agentic capabilities
    const systemPrompt = buildAgenticSystemPrompt(context);
    
    // Initialize conversation messages
    let messages = [
      { role: 'system', content: systemPrompt },
      ...conversationHistory,
      { role: 'user', content: message }
    ];

    // Agentic reasoning loop with tool use
    let iterations = 0;
    let toolCalls = [];
    let finalResponse = '';
    let shouldContinue = true;

    while (shouldContinue && iterations < CONFIG.agentConfig.maxIterations) {
      iterations++;
      console.log(`[Agent] Iteration ${iterations}`);

      // Call OpenRouter API with current conversation state
      const openrouterResponse = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.OPENROUTER_API_KEY}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': new URL(request.url).origin,
          'X-Title': CONFIG.siteName
        },
        body: JSON.stringify({
          model: CONFIG.aiModel, // deepseek/deepseek-chat-v3.1:free
          messages: messages,
          max_tokens: 1024,
          temperature: 0.7
        })
      });

      if (!openrouterResponse.ok) {
        const errorText = await openrouterResponse.text();
        console.error('[Agent] OpenRouter API error:', errorText);
        throw new Error(`OpenRouter API error: ${openrouterResponse.status} - ${errorText}`);
      }

      const aiResponse = await openrouterResponse.json();
      console.log('[Agent] OpenRouter raw response:', JSON.stringify(aiResponse).substring(0, 500));

      // Extract response
      const responseText = extractAIResponse(aiResponse);
      console.log(`[Agent] Extracted AI Response:`, responseText.substring(0, 200));

      // Check if AI wants to use tools
      const toolRequest = parseToolRequest(responseText);
      
      if (toolRequest && CONFIG.enableAgenticAI) {
        console.log(`[Agent] Tool requested:`, toolRequest.tool);
        
        // Execute the tool
        const toolResult = await executeAgentTool(toolRequest.tool, toolRequest.parameters, env);
        
        // Record tool call
        toolCalls.push({
          tool: toolRequest.tool,
          parameters: toolRequest.parameters,
          result: toolResult
        });

        // Add tool result to conversation
        messages.push({
          role: 'assistant',
          content: responseText
        });
        messages.push({
          role: 'user',
          content: `Tool execution result for ${toolRequest.tool}:\n${JSON.stringify(toolResult, null, 2)}\n\nProvide a natural language summary of this result to the user.`
        });

      } else {
        // No more tools needed, this is the final response
        finalResponse = responseText;
        shouldContinue = false;
      }
    }

    // Format response with tool execution history
    const response = {
      success: true,
      message: finalResponse,
      model: CONFIG.aiModel,
      agentic: true,
      iterations: iterations,
      toolCalls: toolCalls.map(tc => ({
        tool: tc.tool,
        success: !tc.result.error
      }))
    };

    console.log(`[Agent] Completed in ${iterations} iterations with ${toolCalls.length} tool calls`);

    const headers = new Headers({ 'Content-Type': 'application/json' });
    addCorsHeaders(headers);
    return new Response(JSON.stringify(response), { headers });

  } catch (error) {
    console.error('[Agent] Error:', error);
    console.error('[Agent] Error stack:', error.stack);
    const response = { 
      success: false, 
      error: error.message || 'AI chat failed',
      errorDetails: error.stack || error.toString(),
      fallback: 'AI assistant is temporarily unavailable. Try searching manually or contact support.'
    };
    const headers = new Headers({ 'Content-Type': 'application/json' });
    addCorsHeaders(headers);
    return new Response(JSON.stringify(response), { status: 500, headers });
  }
}

async function handleDownload(providerConfig, cleanPath, request, ctx) {
  if (!cleanPath) {
    throw { message: "No file path provided", status: 400 };
  }
  
  // Create cache key
  const cacheKey = new Request(request.url.replace("?download", ""), request);
  const cache = caches.default;
  
  // Try to get response from cache first
  let response = await cache.match(cacheKey);
  if (response) {
    // Add cache status header for debugging
    const newHeaders = new Headers(response.headers);
    newHeaders.set("CF-Cache-Status", "HIT");
    newHeaders.set("X-Provider", providerConfig.name);
    addCorsHeaders(newHeaders);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
  }
  
  // Not in cache, fetch from origin
  const startTime = Date.now();
  const rangeHeader = request.headers.get("range") || null;
  const { url, headers } = await signRequest(providerConfig, "GET", cleanPath, {}, "", rangeHeader);
  response = await fetch(url, { headers });
  if (!response.ok && response.status !== 206) {
    const errorText = await response.text();
    throw { message: `Download failed from ${providerConfig.name} (S3 Status: ${response.status}): ${errorText}`, status: response.status };
  }
  
  // ✅ IMPROVEMENT #1 & #2: Cache both full (200) AND partial (206) responses with intelligent duration
  if (response.status === 200 || response.status === 206) {
    // Clone the response before caching since streams can only be read once
    const cacheableResponse = response.clone();
    
    // ✅ IMPROVEMENT #2: Intelligent cache duration based on file size
    const fileSize = parseInt(response.headers.get('content-length') || 0);
    const isLargeFile = fileSize > 100 * 1024 * 1024; // > 100 MB
    const cacheControl = isLargeFile 
      ? "public, max-age=1800, stale-while-revalidate=3600"   // 30 min for large files
      : "public, max-age=7200, stale-while-revalidate=86400"; // 2 hours for small files
    
    // Set cache headers
    const cacheHeaders = new Headers(cacheableResponse.headers);
    cacheHeaders.set("Cache-Control", cacheControl);
    cacheHeaders.set("CF-Cache-Status", "MISS");
    
    // Create a new response with cache headers
    const responseToCache = new Response(cacheableResponse.body, {
      status: cacheableResponse.status,
      statusText: cacheableResponse.statusText,
      headers: cacheHeaders
    });
    
    // Put response in cache
    ctx.waitUntil(cache.put(cacheKey, responseToCache));
  }
  
  const fileName = cleanPath.split("/").pop();
  const fileType = fileName.split(".").pop().toLowerCase();
  const contentType = getContentType(fileType);
  const newHeaders = new Headers(response.headers);
  newHeaders.set("Content-Type", contentType);
  newHeaders.set("Content-Disposition", `attachment; filename="${fileName}"`);
  newHeaders.set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400");
  newHeaders.set("CF-Cache-Status", "MISS");
  newHeaders.set("X-Provider", providerConfig.name);
  
  // ✅ IMPROVEMENT #4: Performance headers
  const duration = Date.now() - startTime;
  newHeaders.set("X-Response-Time", `${duration}ms`);
  
  addCorsHeaders(newHeaders);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
}

async function handleStream(providerConfig, cleanPath, request, ctx) {
  if (!cleanPath) {
    throw { message: "No file path provided", status: 400 };
  }
  
  // Create cache key
  const cacheKey = new Request(request.url.replace("?stream", ""), request);
  const cache = caches.default;
  
  // Try to get response from cache first
  let response = await cache.match(cacheKey);
  if (response) {
    // Add cache status header for debugging
    const newHeaders = new Headers(response.headers);
    newHeaders.set("CF-Cache-Status", "HIT");
    newHeaders.set("X-Provider", providerConfig.name);
    newHeaders.set("X-Response-Time", "0ms"); // Instant from cache
    addCorsHeaders(newHeaders);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
  }
  
  // Not in cache, fetch from origin
  const startTime = Date.now();
  const rangeHeader = request.headers.get("range") || null;
  const { url, headers } = await signRequest(providerConfig, "GET", cleanPath, {}, "", rangeHeader);
  response = await fetch(url, { headers });
  if (!response.ok && response.status !== 206) {
    const errorText = await response.text();
    throw { message: `Stream failed from ${providerConfig.name} (S3 Status: ${response.status}): ${errorText}`, status: response.status };
  }
  
  // ✅ IMPROVEMENT #1 & #2: Cache both full (200) AND partial (206) responses with intelligent duration
  if (response.status === 200 || response.status === 206) {
    // Clone the response before caching since streams can only be read once
    const cacheableResponse = response.clone();
    
    // ✅ IMPROVEMENT #2: Intelligent cache duration based on file size
    const fileSize = parseInt(response.headers.get('content-length') || 0);
    const isLargeFile = fileSize > 100 * 1024 * 1024; // > 100 MB
    const cacheControl = isLargeFile 
      ? "public, max-age=1800, stale-while-revalidate=3600"   // 30 min for large files
      : "public, max-age=7200, stale-while-revalidate=86400"; // 2 hours for small files
    
    // Set cache headers
    const cacheHeaders = new Headers(cacheableResponse.headers);
    cacheHeaders.set("Cache-Control", cacheControl);
    cacheHeaders.set("CF-Cache-Status", "MISS");
    
    // Create a new response with cache headers
    const responseToCache = new Response(cacheableResponse.body, {
      status: cacheableResponse.status,
      statusText: cacheableResponse.statusText,
      headers: cacheHeaders
    });
    
    // Put response in cache
    ctx.waitUntil(cache.put(cacheKey, responseToCache));
  }
  
  const fileName = cleanPath.split("/").pop();
  const fileType = fileName.split(".").pop().toLowerCase();
  let contentType = getContentType(fileType);
  if (fileType === "mkv" && CONFIG.experimentalMkvSupport) {
    contentType = "video/webm";
  }
  const newHeaders = new Headers(response.headers);
  newHeaders.set("Content-Type", contentType);
  newHeaders.set("Content-Disposition", `inline; filename="${fileName}"`);
  newHeaders.set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400");
  newHeaders.set("CF-Cache-Status", response.status === 200 ? "MISS" : "BYPASS");
  newHeaders.set("X-Provider", providerConfig.name);
  
  // ✅ IMPROVEMENT #4: Performance headers
  const duration = Date.now() - startTime;
  newHeaders.set("X-Response-Time", `${duration}ms`);
  
  // ✅ IMPROVEMENT #6: Prefetch next HLS segment for smoother playback
  if (cleanPath.match(/segment-?(\d+)\.(ts|m4s)$/i)) {
    const match = cleanPath.match(/segment-?(\d+)\.(ts|m4s)$/i);
    const currentNum = parseInt(match[1]);
    const extension = match[2];
    const nextSegment = cleanPath.replace(/segment-?(\d+)\.(ts|m4s)$/i, `segment-${currentNum + 1}.${extension}`);
    
    // Prefetch next segment in background (non-blocking)
    ctx.waitUntil(
      (async () => {
        try {
          const { url: nextUrl, headers: nextHeaders } = await signRequest(providerConfig, "GET", nextSegment);
          const nextResponse = await fetch(nextUrl, { headers: nextHeaders });
          if (nextResponse.ok) {
            const nextCacheKey = new Request(request.url.replace(cleanPath, nextSegment).replace("?stream", ""));
            await cache.put(nextCacheKey, nextResponse);
          }
        } catch (e) {
          // Silently fail prefetch - it's optional
        }
      })()
    );
  }
  
  addCorsHeaders(newHeaders);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
}

async function handlePreview(providerConfig, cleanPath, rawPath, request, ctx) {
  if (!cleanPath) {
    throw { message: "No file path provided", status: 400 };
  }
  const fileName = cleanPath.split("/").pop();
  const fileType = fileName.split(".").pop().toLowerCase();
  const videoFormats = ["mp4", "webm", "mkv", "avi", "mov", "m3u8"];
  if (videoFormats.includes(fileType)) {
    const userAgent = request.headers.get("User-Agent") || "";
    const html = await handleVideoPreview(rawPath, fileName, fileType, userAgent);
    return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" }});
  }
  
  // Create cache key
  const cacheKey = new Request(request.url.replace("?preview", ""), request);
  const cache = caches.default;
  
  // Try to get response from cache first
  let response = await cache.match(cacheKey);
  if (response) {
    // Add cache status header for debugging
    const newHeaders = new Headers(response.headers);
    newHeaders.set("CF-Cache-Status", "HIT");
    newHeaders.set("X-Provider", providerConfig.name);
    newHeaders.set("X-Response-Time", "0ms"); // Instant from cache
    addCorsHeaders(newHeaders);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
  }
  
  // Not in cache, fetch from origin
  const startTime = Date.now();
  const rangeHeader = request.headers.get("range") || null;
  const { url, headers } = await signRequest(providerConfig, "GET", cleanPath, {}, "", rangeHeader);
  response = await fetch(url, { headers });
  if (!response.ok && response.status !== 206) {
    const errorText = await response.text();
    throw { message: `Preview failed from ${providerConfig.name} (S3 Status: ${response.status}): ${errorText}`, status: response.status };
  }
  
  // ✅ IMPROVEMENT #1 & #2: Cache both full (200) AND partial (206) responses with intelligent duration
  if (response.status === 200 || response.status === 206) {
    // Clone the response before caching since streams can only be read once
    const cacheableResponse = response.clone();
    
    // ✅ IMPROVEMENT #2: Intelligent cache duration based on file size
    const fileSize = parseInt(response.headers.get('content-length') || 0);
    const isLargeFile = fileSize > 100 * 1024 * 1024; // > 100 MB
    const cacheControl = isLargeFile 
      ? "public, max-age=1800, stale-while-revalidate=3600"   // 30 min for large files
      : "public, max-age=7200, stale-while-revalidate=86400"; // 2 hours for small files
    
    // Set cache headers
    const cacheHeaders = new Headers(cacheableResponse.headers);
    cacheHeaders.set("Cache-Control", cacheControl);
    cacheHeaders.set("CF-Cache-Status", "MISS");
    
    // Create a new response with cache headers
    const responseToCache = new Response(cacheableResponse.body, {
      status: cacheableResponse.status,
      statusText: cacheableResponse.statusText,
      headers: cacheHeaders
    });
    
    // Put response in cache
    ctx.waitUntil(cache.put(cacheKey, responseToCache));
  }
  
  const contentType = getContentType(fileType);
  const newHeaders = new Headers(response.headers);
  newHeaders.set("Content-Type", contentType);
  newHeaders.set("Content-Disposition", `inline; filename="${fileName}"`);
  newHeaders.set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400");
  newHeaders.set("CF-Cache-Status", response.status === 200 ? "MISS" : "BYPASS");
  newHeaders.set("X-Provider", providerConfig.name);
  
  // ✅ IMPROVEMENT #4: Performance headers
  const duration = Date.now() - startTime;
  newHeaders.set("X-Response-Time", `${duration}ms`);
  
  addCorsHeaders(newHeaders);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
}

async function handleVideoPreview(rawPath, fileName, fileType, userAgent) {
  const isFirefox = userAgent.toLowerCase().includes("firefox");
  const isChrome = userAgent.toLowerCase().includes("chrome");
  const isSafari = userAgent.toLowerCase().includes("safari") && !isChrome;
  const streamUrl = `/${rawPath}?stream`;
  let browserInfo = "";
  if (fileType === "mkv" && CONFIG.experimentalMkvSupport) {
    if (isFirefox) {
      browserInfo = `<div class="info-box firefox"><strong>🦊 Firefox Detected</strong><br>Your browser has good native MKV support. If playback fails, the file may use unsupported audio codecs (e.g., AC3, DTS).</div>`;
    } else if (isChrome) {
      browserInfo = `<div class="info-box chrome"><strong>🌐 Chrome Detected</strong><br>Chrome can play some MKV files. If playback fails, try downloading the file or use Firefox for better support.</div>`;
    } else if (isSafari) {
      browserInfo = `<div class="warning"><strong>⚠️ Safari Detected</strong><br>Safari has limited MKV support. We recommend downloading the file or using Firefox/Chrome.</div>`;
    } else {
      browserInfo = `<div class="info-box"><strong>ℹ️ MKV Playback</strong><br>Browser support varies. If playback fails, try downloading or using a different browser.</div>`;
    }
  }
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Preview - ${fileName}</title>
  <style>
    body, html { margin: 0; padding: 0; height: 100%; width: 100%; overflow: hidden; background-color: #000; color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; flex-direction: column; justify-content: center; align-items: center; }
    video { width: 100%; max-height: 90vh; border-radius: 8px; outline: none; }
    .info-container { padding: 20px; max-width: 800px; width: 100%; box-sizing: border-box; }
    .info-box, .warning { padding: 15px 20px; margin-bottom: 20px; border-radius: 6px; font-size: 14px; line-height: 1.6; }
    .info-box { background: #2196f3; }
    .info-box.firefox { background: #ff7139; }
    .info-box.chrome { background: #4285f4; }
    .warning { background: #ff9800; color: #000; }
  </style>
</head>
<body>
  <div class="info-container">${browserInfo}</div>
  <video controls preload="metadata" playsinline>
    ${
      fileType === "mkv" && CONFIG.experimentalMkvSupport
        ? `<source src="${streamUrl}" type="video/webm; codecs=vp9,opus" /><source src="${streamUrl}" type="video/webm; codecs=vp8,opus" /><source src="${streamUrl}" type="video/x-matroska" />`
        : `<source src="${streamUrl}" type="video/${fileType === "mp4" ? "mp4" : fileType === "webm" ? "webm" : "quicktime"}" />`
    }
    Your browser does not support the video tag or this video format.
  </video>
</body>
</html>`;
}

async function handleBrowse(providerConfig, cleanPath, rawPath, request) {
  const prefix = cleanPath ? (cleanPath.endsWith("/") ? cleanPath : cleanPath + "/") : "";
  let result;
  try {
    result = await listObjects(providerConfig, prefix);
  } catch (error) {
    throw error;
  }
  
  // ✅ IMPROVEMENT #8: Mobile detection
  const userAgent = request.headers.get("User-Agent") || "";
  const isMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(userAgent);
  
  const html = getBrowsePage(rawPath, result.folders, result.files, providerConfig, request, isMobile);
  const headers = new Headers({ "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=300" });
  return new Response(html, { headers });
}

// --- HTML PAGE GENERATORS ---

function getContentType(ext) {
  const types = {
    html: "text/html", htm: "text/html", txt: "text/plain", css: "text/css", js: "text/javascript", json: "application/json", xml: "text/xml",
    jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", gif: "image/gif", svg: "image/svg+xml", ico: "image/x-icon", webp: "image/webp",
    mp4: "video/mp4", webm: "video/webm", mkv: "video/x-matroska", avi: "video/x-msvideo", mov: "video/quicktime", m3u8: "application/x-mpegURL",
    mp3: "audio/mpeg", wav: "audio/wav", ogg: "audio/ogg", m4a: "audio/mp4", flac: "audio/flac",
    pdf: "application/pdf", doc: "application/msword", docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xls: "application/vnd.ms-excel", xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ppt: "application/vnd.ms-powerpoint", pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    zip: "application/zip", rar: "application/x-rar-compressed", "7z": "application/x-7z-compressed", tar: "application/x-tar", gz: "application/gzip",
  };
  return types[ext] || "application/octet-stream";
}

function formatSize(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function formatDate(dateString) {
  const date = new Date(dateString);
  return date.toLocaleString();
}

function getFileIcon(name) {
  const ext = name.split(".").pop().toLowerCase();
  const icons = {
    pdf: "📄", doc: "📝", docx: "📝", txt: "📝", xls: "📊", xlsx: "📊", csv: "📊", ppt: "📽️", pptx: "📽️",
    jpg: "🖼️", jpeg: "🖼️", png: "🖼️", gif: "🖼️", svg: "🖼️", webp: "🖼️",
    mp4: "🎬", avi: "🎬", mkv: "🎬", mov: "🎬", webm: "🎬", m3u8: "🎬",
    mp3: "🎵", wav: "🎵", ogg: "🎵", flac: "🎵", m4a: "🎵",
    zip: "📦", rar: "📦", "7z": "📦", tar: "📦", gz: "📦",
    js: "💻", py: "💻", java: "💻", cpp: "💻", html: "💻", css: "💻",
  };
  return icons[ext] || "📄";
}

function getBrowsePage(currentPath, folders, files, providerConfig = null, request, isMobile = false) {
  const baseUrl = new URL(request.url).origin;
  const pathParts = currentPath ? currentPath.split("/").filter((p) => p) : [];
  const breadcrumbs = pathParts.map((part, index) => `<li class="breadcrumb-item"><a href="/${pathParts.slice(0, index + 1).join("/")}">${part}</a></li>`).join("");
  
  // ✅ IMPROVEMENT #8: Mobile-specific message
  const mobileNotice = isMobile ? `<div class="mobile-notice">
    📱 <strong>Mobile Detected:</strong> Use 🚀 CDN links for small files, 🔗 Direct links for large files in MX Player/VLC
  </div>` : '';

  // Theme switcher
  const themeSwitcher = `<div class="theme-switcher">
    <label class="theme-label">🎨 Theme:</label>
    <select id="themeSelect" class="theme-select">
      ${Object.entries(CONFIG.availableThemes).map(([key, theme]) =>
        `<option value="${key}" ${key === CONFIG.theme ? 'selected' : ''}>${theme.name}</option>`
      ).join('')}
    </select>
  </div>`;

  // Provider switcher with modern card design
  const providerSwitcher = `<div class="provider-switcher">
    <div class="provider-grid">${Object.entries(CONFIG.pathRouting).filter(([prefix]) => prefix !== 'default').map(([prefix, providerKey]) => {
      const p = PROVIDERS[providerKey];
      if (!p) return '';
      const isActive = providerConfig?.provider === providerKey;
      return `<div class="provider-card ${isActive ? 'active' : ''}" onclick="window.location.href='/${prefix}'">
        <div class="provider-icon">${p.icon}</div>
        <div class="provider-name">${p.name}</div>
        <div class="provider-desc">${p.description}</div>
      </div>`;
    }).join("")}</div>
    <div class="strategy-badge">Strategy: ${CONFIG.routingStrategy}</div>
  </div>`;

  // Global search box
  const globalSearchBox = `
    <div class="global-search-container">
      <div class="search-icon">🔍</div>
      <input
        type="text"
        class="global-search-input"
        placeholder="Search across all clouds..."
        id="global-search-input"
        onkeypress="if(event.key==='Enter') performGlobalSearch()"
      >
      <button class="search-btn" onclick="performGlobalSearch()">
        Search All Clouds
      </button>
    </div>
  `;

  // Current provider info banner
  const currentProviderInfo = providerConfig ? `<div class="current-provider-banner">
    <div class="provider-info">
      <span class="provider-icon">${providerConfig.icon}</span>
      <span class="provider-text">Currently browsing <strong>${providerConfig.name}</strong></span>
      <span class="provider-desc">${providerConfig.description}</span>
    </div>
  </div>` : '';

  // View switcher with compact mode
  const viewSwitcher = `<div class="view-switcher">
    <button id="gridViewBtn" class="view-btn" onclick="switchView('grid')" title="Grid View">
      <span class="btn-icon">🔲</span>
    </button>
    <button id="listViewBtn" class="view-btn active" onclick="switchView('list')" title="List View">
      <span class="btn-icon">📋</span>
    </button>
    <button id="compactViewBtn" class="view-btn" onclick="toggleCompactMode()" title="Compact Mode">
      <span class="btn-icon">⚡</span>
    </button>
  </div>`;

  // List view column headers (clickable for sorting)
  const listViewHeaders = `<div class="list-view-headers" id="listViewHeaders" style="display:none;">
    <div class="header-cell header-icon"></div>
    <div class="header-cell header-name sortable" onclick="sortByColumn('name')">
      <span>Name</span>
      <span class="sort-indicator" id="sort-name"></span>
    </div>
    <div class="header-cell header-size sortable" onclick="sortByColumn('size')">
      <span>Size</span>
      <span class="sort-indicator" id="sort-size"></span>
    </div>
    <div class="header-cell header-date sortable" onclick="sortByColumn('date')">
      <span>Modified</span>
      <span class="sort-indicator" id="sort-date"></span>
    </div>
    <div class="header-cell header-provider">
      <span>Provider</span>
    </div>
    <div class="header-cell header-actions">Actions</div>
  </div>`;

  // Sort controls with theme switcher and view switcher
  const sortControls = `<div class="sort-controls">
    <div class="sort-group">
      <label class="sort-label">Sort by:</label>
      <select id="sortField" class="sort-select">
        <option value="name">Name</option>
        <option value="size">Size</option>
        <option value="date">Date Modified</option>
      </select>
      <select id="sortDirection" class="sort-select">
        <option value="asc">↑ Ascending</option>
        <option value="desc">↓ Descending</option>
      </select>
      ${viewSwitcher}
    </div>
    <div class="control-group">
      ${themeSwitcher}
      <div class="search-group">
        <input type="text" id="fileSearch" placeholder="Search files and folders..." class="search-input">
        <button class="search-btn" onclick="clearSearch()">✕</button>
      </div>
    </div>
  </div>
  ${listViewHeaders}`;

  // Combine folders and files for sorting
  const allItems = [
    ...folders.map(folder => ({ ...folder, type: 'folder', displayName: folder.name, size: 0, lastModified: '' })),
    ...files.map(file => ({ ...file, type: 'file', displayName: file.name }))
  ];

  // Generate file/folder cards with improved design
  const itemCards = allItems.map(item => {
    if (item.type === 'folder') {
      return `<div class="file-card folder-card" data-name="${item.name.toLowerCase()}" data-size="0" data-date="" data-type="folder">
        <div class="card-header">
          <div class="file-icon-large">📁</div>
          <div class="card-badge">Folder</div>
        </div>
        <div class="card-content">
          <div class="file-name">${item.name}</div>
          <div class="file-meta">
            <div class="meta-item">
              <span class="meta-icon">📁</span>
              <span>Directory</span>
            </div>
            <div class="meta-item">
              <span class="meta-icon">${item.error ? "❌" : PROVIDERS[item.provider]?.icon || ""}</span>
              <span>${item.error ? "Error" : PROVIDERS[item.provider]?.name || ""}</span>
            </div>
          </div>
        </div>
        <div class="card-actions">
          <a href="/${item.prefix}" class="btn btn-primary btn-large">
            <span class="btn-icon">📂</span>
            <span class="btn-text">Open Folder</span>
          </a>
        </div>
      </div>`;
    } else {
      const absoluteStreamUrl = `${baseUrl}/${item.key}?stream`;
      const fileExt = item.name.split('.').pop().toLowerCase();
      
      // File type color coding
      const videoExts = ['mp4', 'webm', 'mkv', 'avi', 'mov', 'm3u8'];
      const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'];
      const audioExts = ['mp3', 'wav', 'ogg', 'm4a', 'flac'];
      const docExts = ['pdf', 'doc', 'docx', 'txt', 'xls', 'xlsx', 'ppt', 'pptx'];
      
      let badgeClass = 'file-badge';
      if (videoExts.includes(fileExt)) badgeClass += ' badge-video';
      else if (imageExts.includes(fileExt)) badgeClass += ' badge-image';
      else if (audioExts.includes(fileExt)) badgeClass += ' badge-audio';
      else if (docExts.includes(fileExt)) badgeClass += ' badge-document';
      
      // Size color coding
      const sizeInMB = item.size / (1024 * 1024);
      let sizeClass = 'size-small';
      if (sizeInMB > 100) sizeClass = 'size-large';
      else if (sizeInMB > 1) sizeClass = 'size-medium';
      
      // ✅ IMPROVEMENT #5: Smart link recommendations based on file size
      const sizeInGB = item.size / (1024 * 1024 * 1024);
      const recommendCDN = sizeInGB < 1; // Recommend CDN for files < 1GB
      const recommendDirect = sizeInGB >= 1; // Recommend Direct for files >= 1GB
      const cdnClass = recommendCDN ? 'btn-recommended' : 'btn-dimmed';
      const directClass = recommendDirect ? 'btn-recommended' : '';
      const cdnBadge = recommendCDN ? '<span class="rec-badge">✨</span>' : '';
      const directBadge = recommendDirect ? '<span class="rec-badge">✨</span>' : '';
      const cdnTitle = recommendCDN 
        ? '🚀 CDN Link (RECOMMENDED ✨) - Fast cached delivery, perfect for files under 1GB' 
        : `🚀 CDN Link - Large file (${formatSize(item.size)}), may not cache efficiently`;
      const directTitle = recommendDirect
        ? `🔗 Direct S3 Link (RECOMMENDED ✨) - Best for large files (${formatSize(item.size)})`
        : '🔗 Direct S3 Link - Best compatibility, direct from S3';

      return `<div class="file-card file-card-item" data-name="${item.name.toLowerCase()}" data-size="${item.size}" data-date="${new Date(item.lastModified).getTime()}" data-type="file" data-provider="${item.provider}" data-path="${item.key}" title="${item.name} - ${formatSize(item.size)} - ${formatDate(item.lastModified)}">
        <input type="checkbox" class="file-checkbox" data-provider="${item.provider}" data-path="${item.key}">
        <div class="card-header">
          <div class="file-icon-large">${getFileIcon(item.name)}</div>
          <div class="card-badge ${badgeClass}">${fileExt.toUpperCase()}</div>
        </div>
        <div class="card-content">
          <div class="file-name" title="${item.name}">${item.name}</div>
          <div class="file-meta">
            <div class="meta-item">
              <span class="meta-icon">📏</span>
              <span class="${sizeClass}">${formatSize(item.size)}</span>
            </div>
            <div class="meta-item">
              <span class="meta-icon">📅</span>
              <span>${formatDate(item.lastModified)}</span>
            </div>
            <div class="meta-item">
              <span class="meta-icon">${item.providerIcon}</span>
              <span>${item.providerName}</span>
            </div>
          </div>
        </div>
        <div class="card-actions">
          <button class="btn btn-download" onclick="downloadFile('${item.key}', this)" title="Download ${item.name}">
            <span class="btn-icon">⬇️</span>
          </button>
          <button class="btn btn-copy" onclick="copyToClipboard('${absoluteStreamUrl}', this)" title="Copy Stream Link">
            <span class="btn-icon">📋</span>
          </button>
          <button class="btn btn-cdn ${cdnClass}" onclick="generateShareLink('${item.key}', this, true)" title="${cdnTitle}">
            <span class="btn-icon">🚀</span>${cdnBadge}
          </button>
          <button class="btn btn-share ${directClass}" onclick="generateShareLink('${item.key}', this, false)" title="${directTitle}">
            <span class="btn-icon">🔗</span>${directBadge}
          </button>
          ${isPreviewable(item.name) ? `<button class="btn btn-preview" onclick="previewFile('${item.key}', this)" title="Preview ${item.name}">
            <span class="btn-icon">👁️</span>
          </button>` : ""}
          <button class="btn btn-delete" onclick="deleteFile('${item.key}', this)" title="Delete ${item.name}">
            <span class="btn-icon">🗑️</span>
          </button>
        </div>
      </div>`;
    }
  }).join("");
  
  const emptyState = folders.length === 0 && files.length === 0 ? `<div class="empty-state">
    <div class="empty-icon">📭</div>
    <h2 class="empty-title">This folder is empty</h2>
    <p class="empty-description">No files or folders found in this location.</p>
    <div class="empty-suggestions">
      <p class="empty-suggestion-title">💡 What you can do:</p>
      <ul class="empty-suggestion-list">
        <li>Upload files to this bucket from your S3 console</li>
        <li>Check if you're in the correct path</li>
        <li>Navigate to a different folder using the breadcrumbs above</li>
        <li>Try refreshing the page</li>
      </ul>
    </div>
    <button class="btn btn-primary btn-large" onclick="goBack()">
      <span class="btn-icon">←</span>
      <span class="btn-text">Go Back</span>
    </button>
  </div>` : '';

  const fileGrid = `<div class="file-grid" id="fileGrid">${itemCards}</div>`;

  const selectAllCheckbox = folders.length === 0 && files.length === 0 ? '' : `
<div class="select-all-container">
  <input type="checkbox" id="select-all-checkbox" onchange="toggleSelectAll(this)">
  <label for="select-all-checkbox">Select All Files</label>
  <span style="margin-left: auto; color: var(--text-secondary);">
    <span id="selected-count">0</span> selected
  </span>
</div>
`;

  const bulkToolbar = `
<div id="bulk-toolbar" class="bulk-toolbar">
  <span class="bulk-count"><span id="bulk-count">0</span> files selected</span>
  <button class="bulk-action-btn bulk-export-cdn" onclick="bulkExport('cdn')" title="Export CDN Links">🚀 CDN Links</button>
  <button class="bulk-action-btn bulk-export-direct" onclick="bulkExport('direct')" title="Export Direct Links">🔗 Direct Links</button>
  <button class="bulk-action-btn bulk-export-download" onclick="bulkExport('download')" title="Export Download Links">⬇️ Download Links</button>
  <button class="bulk-action-btn bulk-export-both" onclick="bulkExport('both')" title="Export All">📋 All Links</button>
  <button class="bulk-action-btn bulk-export-json" onclick="bulkExport('json')" title="Export as JSON">📄 JSON</button>
  <button class="bulk-action-btn bulk-export-md" onclick="bulkExport('markdown')" title="Export as Markdown">📝 MD</button>
  <button class="bulk-action-btn bulk-delete-btn" onclick="bulkDeleteFiles()" title="Delete Selected Files">🗑️ Delete</button>
  <button class="bulk-action-btn bulk-clear-btn" onclick="clearSelection()" title="Clear Selection">✖️ Clear</button>
</div>
`;

  const aiChatWidget = CONFIG.enableAIChat ? `
<div class="ai-chat-widget">
  <button class="ai-chat-toggle" onclick="toggleAIChat()" title="Agentic AI Assistant">
    🤖 AI Agent ${CONFIG.enableAgenticAI ? '⚡' : ''}
  </button>
  
  <div class="ai-chat-panel" id="aiChatPanel" style="display:none;">
    <div class="ai-chat-header">
      <span class="ai-chat-title">🤖 ${CONFIG.enableAgenticAI ? 'Agentic AI Assistant ⚡' : 'AI File Assistant'}</span>
      <button class="ai-chat-close" onclick="toggleAIChat()" title="Close">✖️</button>
    </div>
    
    <div class="ai-chat-messages" id="aiChatMessages">
      <div class="ai-message ai-assistant">
        <div class="ai-message-content">
          👋 Hi! I'm your ${CONFIG.enableAgenticAI ? 'autonomous AI agent' : 'AI file assistant'}. ${CONFIG.enableAgenticAI ? 'I can autonomously execute tasks and use tools to help you manage your multi-cloud storage.' : 'I can help you manage your files.'}
          <br><br>
          <strong>🔧 My Capabilities:</strong>
          <ul>
            <li>🔍 <strong>Search files</strong> across all cloud providers</li>
            <li>📊 <strong>Analyze storage</strong> usage and patterns</li>
            <li>🔗 <strong>Generate links</strong> (download, share, streaming, direct)</li>
            <li>📁 <strong>Organize files</strong> by type, date, or size</li>
            <li>🗑️ <strong>Delete files</strong> with safety checks</li>
            <li>💡 <strong>Generate insights</strong> and recommendations</li>
            ${CONFIG.enableAgenticAI ? '<li>⚡ <strong>Autonomous execution</strong> - I can take action directly!</li>' : ''}
          </ul>
          <strong>💬 Try asking:</strong>
          <ul>
            <li>"Search for all MP4 files in Wasabi"</li>
            <li>"Generate all links for video.mp4"</li>
            <li>"Analyze my storage usage across all providers"</li>
            <li>"What are my largest files?"</li>
            <li>"Find and delete duplicate files"</li>
            <li>"How can I optimize my storage?"</li>
          </ul>
        </div>
      </div>
    </div>
    
    <div class="ai-chat-input-container">
      <input type="text" class="ai-chat-input" id="aiChatInput" 
             placeholder="${CONFIG.enableAgenticAI ? 'Tell me what to do... I can execute tasks!' : 'Ask me anything about your files...'}" 
             onkeypress="handleAIChatKey(event)">
      <button class="ai-chat-send" onclick="sendAIMessage()" title="Send message">
        <span>Send</span>
      </button>
    </div>
  </div>
</div>
` : '';

  // Get current theme colors
  const currentTheme = CONFIG.availableThemes[CONFIG.theme];
  
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>${CONFIG.siteName}</title>
<style>
  :root {
    /* Current Theme Colors */
    --bg-gradient: ${currentTheme.background};
    --surface: ${currentTheme.surface};
    --surface-secondary: ${currentTheme.surfaceSecondary};
    --text: ${currentTheme.text};
    --text-secondary: ${currentTheme.textSecondary};
    --accent: ${currentTheme.accent};
    --accent-secondary: ${currentTheme.accentSecondary};
    --border: ${currentTheme.border};
    --success: ${currentTheme.success};
    --error: ${currentTheme.error};
    --warning: ${currentTheme.warning};

    /* Spacing and Layout */
    --border-radius: 16px;
    --border-radius-sm: 12px;
    --border-radius-xs: 8px;
    --shadow: 0 4px 20px rgba(0,0,0,0.08);
    --shadow-hover: 0 12px 32px rgba(0,0,0,0.12);
    --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }

  *{margin:0;padding:0;box-sizing:border-box}

  body{
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;
    background:var(--bg-gradient);
    background-attachment:fixed;
    min-height:100vh;
    color:var(--text);
    line-height:1.6;
    transition:var(--transition);
  }

  .container{
    max-width:1400px;
    margin:0 auto;
    background:var(--surface);
    backdrop-filter:blur(20px);
    -webkit-backdrop-filter:blur(20px);
    border-radius:var(--border-radius);
    box-shadow:var(--shadow);
    margin:20px;
    padding:30px;
    transition:var(--transition);
  }

  /* Header Styles */
  header{
    display:flex;
    align-items:center;
    margin-bottom:30px;
    padding-bottom:20px;
    border-bottom:2px solid var(--border);
    transition:var(--transition);
  }

  .header-content{
    display:flex;
    justify-content:space-between;
    width:100%;
    align-items:center;
  }

  .logo-section{
    display:flex;
    align-items:center;
  }

  .site-icon{
    font-size:48px;
    margin-right:20px;
    filter:drop-shadow(0 2px 8px rgba(0,0,0,0.1));
  }

  .title-section h1{
    font-size:32px;
    font-weight:700;
    margin:0;
    background:linear-gradient(135deg, var(--accent), var(--text));
    -webkit-background-clip:text;
    -webkit-text-fill-color:transparent;
    background-clip:text;
  }

  .subtitle{
    font-size:14px;
    color:var(--text-secondary);
    margin-top:5px;
  }

  .header-stats{
    display:flex;
    gap:20px;
  }

  .stat-item{
    display:flex;
    align-items:center;
    gap:8px;
    font-size:14px;
    color:var(--text-secondary);
    padding:8px 16px;
    background:var(--surface-secondary);
    border-radius:20px;
    border:1px solid var(--border);
  }

  /* Theme Switcher */
  .theme-switcher{
    display:flex;
    align-items:center;
    gap:10px;
  }

  .theme-label{
    font-weight:600;
    color:var(--text-secondary);
    font-size:14px;
  }

  .theme-select{
    padding:8px 12px;
    border:1px solid var(--border);
    border-radius:8px;
    font-size:14px;
    background:var(--surface);
    color:var(--text);
    cursor:pointer;
    transition:var(--transition);
  }

  .theme-select:hover{
    border-color:var(--accent);
  }

  .theme-select:focus{
    outline:none;
    border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(74, 144, 226, 0.1);
  }

  /* Provider Switcher */
  .provider-switcher{
    margin-bottom:25px;
  }

  .provider-grid{
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
    gap:16px;
    margin-bottom:16px;
  }

  .provider-card{
    background:var(--surface);
    border:2px solid var(--border);
    border-radius:var(--border-radius-sm);
    padding:20px;
    cursor:pointer;
    transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    text-align:center;
    box-shadow:var(--shadow);
    position:relative;
    overflow:hidden;
    display:flex;
    flex-direction:column;
    align-items:center;
    justify-content:center;
  }

  .provider-card::before{
    content:'';
    position:absolute;
    top:0;
    left:0;
    right:0;
    height:4px;
    background:linear-gradient(90deg, var(--accent), var(--warning));
    opacity:0;
    transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }

  .provider-card:hover{
    transform:translateY(-6px) scale(1.02);
    box-shadow:var(--shadow-hover);
    border-color:var(--accent);
  }

  .provider-card:hover::before{
    opacity:1;
  }

  .provider-card.active{
    border-color:var(--accent);
    background:var(--accent-secondary);
    transform:translateY(-2px);
  }

  .provider-card.active::before{
    opacity:1;
  }

  .provider-icon{
    font-size:32px;
    margin-bottom:16px;
    display:block;
    transition:transform 0.3s ease;
  }

  .provider-card:hover .provider-icon{
    transform:scale(1.1);
  }

  .provider-name{
    font-weight:600;
    margin-bottom:8px;
    font-size:18px;
    transition:color 0.3s ease;
  }

  .provider-card:hover .provider-name{
    color:var(--accent);
  }

  .provider-desc{
    font-size:13px;
    color:var(--text-secondary);
    line-height:1.5;
    transition:color 0.3s ease;
  }

  .strategy-badge{
    margin-top:16px;
    text-align:center;
    font-size:12px;
    color:var(--text-secondary);
    background:var(--surface-secondary);
    padding:6px 12px;
    border-radius:20px;
    display:inline-block;
    border:1px solid var(--border);
  }

  /* Current Provider Banner */
  .current-provider-banner{
    background:linear-gradient(135deg, var(--accent), var(--warning));
    color:white;
    padding:16px 24px;
    border-radius:var(--border-radius-sm);
    margin-bottom:20px;
    box-shadow:var(--shadow);
  }
  
  /* ✅ IMPROVEMENT #8: Mobile notice styling */
  .mobile-notice{
    background:linear-gradient(135deg, #4caf50, #8bc34a);
    color:white;
    padding:14px 20px;
    border-radius:var(--border-radius-sm);
    margin-bottom:20px;
    box-shadow:var(--shadow);
    font-size:14px;
    text-align:center;
    border:2px solid rgba(255,255,255,0.3);
  }

  .provider-info{
    display:flex;
    align-items:center;
    gap:12px;
    flex-wrap:wrap;
  }

  .provider-info .provider-icon{
    font-size:24px;
  }

  .provider-info .provider-text{
    font-size:15px;
    font-weight:500;
  }

  .provider-info .provider-desc{
    font-size:13px;
    opacity:0.9;
    margin-left:auto;
  }

  /* Breadcrumb */
  .breadcrumb{
    margin-bottom:25px;
  }

  .breadcrumb nav{
    background:var(--surface);
    padding:16px 24px;
    border-radius:var(--border-radius-sm);
    box-shadow:var(--shadow);
    border:1px solid var(--border);
  }

  .breadcrumb-list{
    display:flex;
    gap:8px;
    font-size:14px;
    flex-wrap:wrap;
  }

  .breadcrumb-item{
    display:flex;
    align-items:center;
  }

  .breadcrumb-item:not(:last-child)::after{
    content:"/";
    margin-left:8px;
    color:var(--text-secondary);
  }

  .breadcrumb-link{
    color:var(--accent);
    text-decoration:none;
    padding:6px 12px;
    border-radius:6px;
    transition:var(--transition);
    font-weight:500;
  }

  .breadcrumb-link:hover{
    background:var(--accent-secondary);
    color:var(--accent);
  }

  /* Sort Controls */
  .sort-controls{
    display:flex;
    justify-content:space-between;
    align-items:center;
    margin-bottom:25px;
    background:var(--surface);
    padding:20px 24px;
    border-radius:var(--border-radius-sm);
    box-shadow:var(--shadow);
    border:1px solid var(--border);
    flex-wrap:wrap;
    gap:16px;
  }

  .sort-group{
    display:flex;
    align-items:center;
    gap:12px;
  }

  .sort-label{
    font-weight:600;
    color:var(--text-secondary);
    font-size:14px;
  }

  .sort-select{
    padding:10px 14px;
    border:1px solid var(--border);
    border-radius:8px;
    font-size:14px;
    background:var(--surface);
    color:var(--text);
    cursor:pointer;
    transition:var(--transition);
    min-width:120px;
  }

  .sort-select:hover{
    border-color:var(--accent);
  }

  .sort-select:focus{
    outline:none;
    border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(74, 144, 226, 0.1);
  }

  .control-group{
    display:flex;
    gap:16px;
    align-items:center;
    flex-wrap:wrap;
  }

  .search-group{
    display:flex;
    gap:8px;
  }

  .search-input{
    flex:1;
    padding:10px 16px;
    border:1px solid var(--border);
    border-radius:8px;
    font-size:14px;
    min-width:250px;
    background:var(--surface);
    color:var(--text);
    transition:var(--transition);
  }

  .search-input:focus{
    outline:none;
    border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(74, 144, 226, 0.1);
  }

  .search-input::placeholder{
    color:var(--text-secondary);
  }

  .search-btn{
    background:var(--surface-secondary);
    border:1px solid var(--border);
    padding:10px 14px;
    border-radius:8px;
    cursor:pointer;
    font-size:14px;
    color:var(--text-secondary);
    transition:var(--transition);
  }

  .search-btn:hover{
    background:var(--accent-secondary);
    border-color:var(--accent);
    color:var(--accent);
  }

  /* View Switcher */
  .view-switcher{
    display:flex;
    gap:4px;
    margin-left:16px;
    border:1px solid var(--border);
    border-radius:8px;
    padding:4px;
    background:var(--surface-secondary);
  }

  .view-btn{
    background:transparent;
    border:none;
    padding:8px 12px;
    border-radius:6px;
    cursor:pointer;
    font-size:14px;
    color:var(--text-secondary);
    transition:var(--transition);
    display:flex;
    align-items:center;
    justify-content:center;
  }

  .view-btn:hover{
    background:var(--surface);
    color:var(--text);
  }

  .view-btn.active{
    background:var(--accent);
    color:white;
  }

  /* List View Column Headers */
  .list-view-headers{
    display:flex;
    align-items:center;
    background:var(--surface-secondary);
    padding:12px 24px;
    border-radius:var(--border-radius-sm);
    margin-bottom:16px;
    border:1px solid var(--border);
    gap:20px;
    font-weight:600;
    font-size:13px;
    color:var(--text-secondary);
    text-transform:uppercase;
    letter-spacing:0.5px;
  }

  .header-cell{
    display:flex;
    align-items:center;
    gap:6px;
  }

  .header-icon{
    width:80px;
    flex-shrink:0;
  }

  .header-name{
    flex:1;
    min-width:200px;
  }

  .header-size{
    width:120px;
    flex-shrink:0;
  }

  .header-date{
    width:180px;
    flex-shrink:0;
  }

  .header-provider{
    width:150px;
    flex-shrink:0;
  }

  .header-actions{
    width:220px;
    flex-shrink:0;
    text-align:right;
  }

  .sortable{
    cursor:pointer;
    user-select:none;
    transition:var(--transition);
  }

  .sortable:hover{
    color:var(--accent);
  }

  .sort-indicator{
    opacity:0;
    transition:var(--transition);
  }

  .sort-indicator.active{
    opacity:1;
    color:var(--accent);
  }

  /* File Grid */
  .file-grid{
    display:grid;
    grid-template-columns:repeat(auto-fill,minmax(380px,1fr));
    gap:24px;
    margin-bottom:30px;
  }

  /* List View */
  .file-grid.list-view{
    display:flex;
    flex-direction:column;
    gap:12px;
  }

  .file-grid.list-view .file-card{
    display:flex;
    flex-direction:row;
    align-items:center;
    padding:16px 24px;
    gap:20px;
  }

  .file-grid.list-view .card-header{
    flex-direction:row;
    padding:0;
    border:none;
    background:transparent;
    width:auto;
    gap:12px;
    align-items:center;
    min-width:120px;
  }

  .file-grid.list-view .file-icon-large{
    font-size:2rem;
  }

  .file-grid.list-view .card-badge{
    padding:3px 8px;
    font-size:10px;
  }

  .file-grid.list-view .card-content{
    flex:1;
    padding:0;
    display:flex;
    flex-direction:row;
    align-items:center;
    gap:24px;
  }

  .file-grid.list-view .file-name{
    flex:1;
    font-size:15px;
    margin:0;
    min-width:200px;
  }

  .file-grid.list-view .file-meta{
    flex-direction:row;
    gap:20px;
    flex-wrap:wrap;
  }

  .file-grid.list-view .meta-item{
    font-size:12px;
  }

  .file-grid.list-view .card-actions{
    padding:0;
    border:none;
    background:transparent;
    gap:6px;
    flex-shrink:0;
  }

  .file-grid.list-view .btn{
    width:36px;
    height:36px;
  }

  .file-grid.list-view .btn-icon{
    font-size:14px;
  }

  .file-grid.list-view .btn-large{
    width:auto;
    padding:10px 20px;
  }

  /* Compact Mode */
  .file-grid.compact-mode .file-card{
    padding:8px 16px;
    gap:12px;
  }

  .file-grid.compact-mode .card-header{
    padding:0;
    min-width:80px;
  }

  .file-grid.compact-mode .file-icon-large{
    font-size:1.5rem;
  }

  .file-grid.compact-mode .card-badge{
    padding:2px 6px;
    font-size:9px;
  }

  .file-grid.compact-mode .card-content{
    padding:0;
    gap:16px;
  }

  .file-grid.compact-mode .file-name{
    font-size:14px;
    min-width:150px;
  }

  .file-grid.compact-mode .file-meta{
    gap:16px;
  }

  .file-grid.compact-mode .meta-item{
    font-size:11px;
  }

  .file-grid.compact-mode .btn{
    width:32px;
    height:32px;
  }

  .file-grid.compact-mode .btn-icon{
    font-size:12px;
  }

  .file-card{
    background:var(--surface);
    border-radius:var(--border-radius-sm);
    padding:0;
    box-shadow:var(--shadow);
    transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    border:1px solid var(--border);
    overflow:hidden;
    position:relative;
    display:flex;
    flex-direction:column;
    height:100%;
  }

  .file-card:hover{
    transform:translateY(-6px) scale(1.01);
    box-shadow:var(--shadow-hover);
    border-color:var(--accent);
    animation:pulse 0.6s ease-in-out;
  }

  @keyframes pulse{
    0%, 100%{transform:translateY(-6px) scale(1.01)}
    50%{transform:translateY(-6px) scale(1.02)}
  }

  .folder-card{
    border-left:4px solid var(--accent);
  }

  .file-card-item{
    border-left:4px solid var(--success);
  }

  /* Card Header */
  .card-header{
    display:flex;
    align-items:center;
    justify-content:space-between;
    padding:20px 24px 16px;
    border-bottom:1px solid var(--border);
    background:linear-gradient(135deg, var(--surface-secondary), var(--surface));
  }

  .file-icon-large{
    font-size:3rem;
    filter:drop-shadow(0 2px 8px rgba(0,0,0,0.1));
    transition:transform 0.3s ease;
  }

  .file-card:hover .file-icon-large{
    transform:scale(1.1);
  }

  .card-badge{
    background:var(--accent);
    color:white;
    padding:4px 12px;
    border-radius:12px;
    font-size:11px;
    font-weight:600;
    text-transform:uppercase;
    letter-spacing:0.5px;
  }

  .file-badge{
    background:var(--success);
  }

  /* File type color badges */
  .badge-video{
    background:#dc3545 !important;
  }

  .badge-image{
    background:#4a90e2 !important;
  }

  .badge-audio{
    background:#a855f7 !important;
  }

  .badge-document{
    background:#28a745 !important;
  }

  /* Size color coding */
  .size-small{
    color:var(--success);
    font-weight:600;
  }

  .size-medium{
    color:var(--warning);
    font-weight:600;
  }

  .size-large{
    color:var(--error);
    font-weight:600;
  }

  /* Card Content */
  .card-content{
    padding:20px 24px;
    flex:1;
    display:flex;
    flex-direction:column;
  }

  .file-name{
    font-weight:600;
    margin-bottom:12px;
    font-size:18px;
    line-height:1.3;
    color:var(--text);
    word-break:break-word;
    display:-webkit-box;
    -webkit-line-clamp:2;
    -webkit-box-orient:vertical;
    overflow:hidden;
    flex:1;
  }

  .file-meta{
    display:flex;
    flex-direction:column;
    gap:8px;
    margin-top:auto;
    padding-top:12px;
    border-top:1px solid var(--border);
  }

  .meta-item{
    display:flex;
    align-items:center;
    gap:8px;
    font-size:13px;
    color:var(--text-secondary);
  }

  .meta-icon{
    font-size:14px;
    width:16px;
    text-align:center;
  }

  /* Card Actions */
  .card-actions{
    padding:16px 24px 20px;
    border-top:1px solid var(--border);
    background:var(--surface-secondary);
    display:flex;
    gap:8px;
    justify-content:flex-end;
  }

  .btn{
    padding:0;
    border-radius:8px;
    border:none;
    cursor:pointer;
    transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    font-size:14px;
    display:flex;
    align-items:center;
    justify-content:center;
    width:44px;
    height:44px;
    position:relative;
    overflow:hidden;
    box-shadow:0 2px 4px rgba(0,0,0,0.1);
  }

  .btn::before{
    content:'';
    position:absolute;
    top:50%;
    left:50%;
    width:0;
    height:0;
    background:rgba(255,255,255,0.2);
    border-radius:50%;
    transform:translate(-50%, -50%);
    transition:width 0.3s, height 0.3s;
  }

  .btn:hover::before{
    width:120%;
    height:120%;
  }

  .btn:hover{
    transform:scale(1.05);
    box-shadow:0 4px 8px rgba(0,0,0,0.15);
  }

  .btn:active{
    transform:scale(0.95);
  }

  .btn:disabled{
    opacity:0.6;
    cursor:not-allowed;
    transform:none;
  }

  .btn:disabled::before{
    display:none;
  }

  .btn:disabled:hover{
    transform:none;
    box-shadow:0 2px 4px rgba(0,0,0,0.1);
  }

  .btn-primary{
    background:var(--accent);
    color:white;
    width:auto;
    padding:0 20px;
    box-shadow:0 2px 8px rgba(0,0,0,0.1);
  }

  .btn-primary:hover{
    background:var(--accent);
    box-shadow:0 4px 16px rgba(0,0,0,0.15);
  }

  .btn-large{
    width:auto;
    padding:12px 24px;
    gap:8px;
  }

  .btn-icon{
    font-size:16px;
    z-index:1;
    position:relative;
  }

  .btn-text{
    font-weight:500;
    z-index:1;
    position:relative;
  }

  .btn-download{
    background:var(--success);
    color:white;
  }

  .btn-copy{
    background:#6f42c1;
    color:white;
  }

  .btn-cdn{
    background:#28a745;
    color:white;
  }

  .btn-share{
    background:var(--warning);
    color:white;
  }
  
  /* ✅ IMPROVEMENT #5: Recommended button styling */
  .btn-recommended{
    position:relative;
    box-shadow:0 0 0 2px var(--accent), 0 4px 12px rgba(77, 159, 255, 0.3) !important;
    animation:pulse-glow 2s ease-in-out infinite;
  }
  
  @keyframes pulse-glow{
    0%, 100%{box-shadow:0 0 0 2px var(--accent), 0 4px 12px rgba(77, 159, 255, 0.3)}
    50%{box-shadow:0 0 0 2px var(--accent), 0 4px 16px rgba(77, 159, 255, 0.5)}
  }
  
  .btn-dimmed{
    opacity:0.5;
  }
  
  .btn-dimmed:hover{
    opacity:0.7;
  }
  
  .rec-badge{
    position:absolute;
    top:-4px;
    right:-4px;
    font-size:10px;
    animation:sparkle 1.5s ease-in-out infinite;
  }
  
  @keyframes sparkle{
    0%, 100%{transform:scale(1) rotate(0deg)}
    50%{transform:scale(1.2) rotate(15deg)}
  }

  .btn-preview{
    background:#17a2b8;
    color:white;
  }

  .btn-delete{
    background:var(--error);
    color:white;
  }

  /* Empty State */
  .empty-state{
    text-align:center;
    padding:100px 40px;
    background:var(--surface);
    border-radius:var(--border-radius-sm);
    margin:40px 0;
    border:2px dashed var(--border);
  }

  .empty-icon{
    font-size:80px;
    margin-bottom:24px;
    opacity:0.6;
    animation:float 3s ease-in-out infinite;
  }

  @keyframes float{
    0%, 100%{transform:translateY(0)}
    50%{transform:translateY(-10px)}
  }

  .empty-title{
    font-size:28px;
    margin-bottom:12px;
    color:var(--text-secondary);
    font-weight:600;
  }

  .empty-description{
    color:var(--text-secondary);
    margin-bottom:24px;
    font-size:16px;
  }

  .empty-suggestions{
    background:var(--surface-secondary);
    padding:20px;
    border-radius:8px;
    margin-bottom:32px;
    text-align:left;
    max-width:500px;
    margin-left:auto;
    margin-right:auto;
  }

  .empty-suggestion-title{
    font-weight:600;
    margin-bottom:12px;
    color:var(--accent);
  }

  .empty-suggestion-list{
    list-style:none;
    padding:0;
  }

  .empty-suggestion-list li{
    padding:8px 0;
    padding-left:24px;
    position:relative;
    color:var(--text-secondary);
    line-height:1.5;
  }

  .empty-suggestion-list li::before{
    content:'•';
    position:absolute;
    left:8px;
    color:var(--accent);
    font-weight:bold;
  }

  /* Stats */
  .stats{
    background:var(--surface);
    padding:24px;
    border-radius:var(--border-radius-sm);
    display:flex;
    gap:32px;
    flex-wrap:wrap;
    margin-bottom:30px;
    box-shadow:var(--shadow);
    border:1px solid var(--border);
  }

  .stat{
    display:flex;
    align-items:center;
    gap:10px;
    font-size:15px;
    color:var(--text-secondary);
    font-weight:500;
  }

  .stat-icon{
    font-size:18px;
  }

  /* Footer */
  footer{
    text-align:center;
    margin-top:40px;
    padding-top:24px;
    border-top:1px solid var(--border);
    color:var(--text-secondary);
    font-size:14px;
  }

  footer p{
    margin:8px 0;
  }

  /* Keyboard Shortcuts */
  .keyboard-shortcuts{
    margin-top:20px;
    position:relative;
  }

  .shortcuts-toggle{
    background:var(--surface-secondary);
    border:1px solid var(--border);
    padding:10px 20px;
    border-radius:8px;
    cursor:pointer;
    font-size:14px;
    color:var(--text);
    transition:var(--transition);
  }

  .shortcuts-toggle:hover{
    background:var(--accent-secondary);
    border-color:var(--accent);
    color:var(--accent);
  }

  .shortcuts-panel{
    position:fixed;
    bottom:20px;
    right:20px;
    background:var(--surface);
    border:2px solid var(--accent);
    border-radius:var(--border-radius-sm);
    padding:24px;
    box-shadow:var(--shadow-hover);
    z-index:9999;
    opacity:0;
    transform:translateY(20px);
    pointer-events:none;
    transition:var(--transition);
    max-width:400px;
  }

  .shortcuts-panel.show{
    opacity:1;
    transform:translateY(0);
    pointer-events:auto;
  }

  .shortcuts-content h3{
    margin-top:0;
    margin-bottom:16px;
    color:var(--accent);
  }

  .shortcuts-grid{
    display:grid;
    gap:12px;
  }

  .shortcut-item{
    display:flex;
    align-items:center;
    gap:12px;
  }

  .shortcut-item kbd{
    background:var(--surface-secondary);
    border:1px solid var(--border);
    border-radius:4px;
    padding:4px 8px;
    font-size:12px;
    font-family:monospace;
    min-width:32px;
    text-align:center;
    display:inline-block;
    box-shadow:0 2px 0 var(--border);
  }

  .shortcut-item span{
    color:var(--text-secondary);
    font-size:14px;
  }

  /* Toast Notifications */
  .toast{
    position:fixed;
    top:24px;
    right:24px;
    background:var(--surface);
    color:var(--text);
    padding:16px 20px;
    border-radius:12px;
    box-shadow:0 8px 32px rgba(0,0,0,0.15);
    z-index:10000;
    opacity:0;
    transform:translateY(-20px);
    transition:var(--transition);
    border:1px solid var(--border);
    max-width:400px;
  }

  .toast.show{
    opacity:1;
    transform:translateY(0);
  }

  .toast.success{
    border-color:var(--success);
    background:linear-gradient(135deg, var(--surface), rgba(40, 167, 69, 0.05));
  }

  .toast.error{
    border-color:var(--error);
    background:linear-gradient(135deg, var(--surface), rgba(220, 53, 69, 0.05));
  }

  .toast-close{
    position:absolute;
    top:8px;
    right:12px;
    background:none;
    border:none;
    color:var(--text-secondary);
    font-size:20px;
    cursor:pointer;
    padding:0;
    width:24px;
    height:24px;
    display:flex;
    align-items:center;
    justify-content:center;
    border-radius:4px;
    transition:var(--transition);
  }

  .toast-close:hover{
    background:var(--surface-secondary);
    color:var(--text);
  }

  /* Loading Spinner */
  .loading-spinner{
    display:inline-block;
    width:18px;
    height:18px;
    border:2px solid rgba(255,255,255,0.3);
    border-top:2px solid white;
    border-radius:50%;
    animation:spin 1s linear infinite;
  }

  @keyframes spin{
    0%{transform:rotate(0deg)}
    100%{transform:rotate(360deg)}
  }

  /* Global Loading Indicator */
  .global-loading{
    position:fixed;
    top:0;
    left:0;
    width:100%;
    height:4px;
    background:var(--surface);
    z-index:9999;
    opacity:0;
    transition:opacity 0.3s ease;
  }

  .global-loading.show{
    opacity:1;
  }

  .global-loading-bar{
    height:100%;
    width:0%;
    background:var(--accent);
    transition:width 0.3s ease;
  }

  /* Skeleton Loading */
  .skeleton{
    background:linear-gradient(90deg, var(--surface-secondary) 25%, var(--surface) 50%, var(--surface-secondary) 75%);
    background-size:200% 100%;
    animation:shimmer 1.5s infinite;
    border-radius:4px;
  }

  @keyframes shimmer{
    0%{background-position:200% 0}
    100%{background-position:-200% 0}
  }

  .file-card.loading{
    pointer-events:none;
    opacity:0.6;
  }

  .file-card.loading .file-name,
  .file-card.loading .meta-item span{
    background:linear-gradient(90deg, var(--surface-secondary) 25%, var(--surface) 50%, var(--surface-secondary) 75%);
    background-size:200% 100%;
    animation:shimmer 1.5s infinite;
    color:transparent;
    border-radius:4px;
  }

  /* Responsive Design */
  @media (max-width:1200px){
    .file-grid{grid-template-columns:repeat(auto-fill,minmax(340px,1fr))}
  }

  @media (max-width:1024px){
    .file-grid{grid-template-columns:repeat(auto-fill,minmax(320px,1fr))}
    .sort-controls{flex-direction:column;gap:20px}
    .control-group{justify-content:center}
  }

  @media (max-width:768px){
    .container{margin:16px;padding:24px}
    .header-content{flex-direction:column;gap:20px;text-align:center}
    .file-grid{grid-template-columns:1fr}
    .file-card{flex-direction:column;text-align:center}
    .card-actions{justify-content:center;flex-wrap:wrap}
    .provider-grid{grid-template-columns:1fr}
    .stats{flex-direction:column;gap:16px}
    .breadcrumb-list{flex-wrap:wrap}
    .control-group{flex-direction:column;gap:12px}
    .search-input{min-width:auto;width:100%}
    .sort-group{flex-wrap:wrap;justify-content:center}
    .view-switcher{margin-left:0;margin-top:8px}

    /* Force list view layout on mobile */
    .file-grid.list-view .file-card{
      flex-direction:column;
      text-align:center;
      padding:0;
    }

    .file-grid.list-view .card-header{
      flex-direction:column;
      padding:20px 24px 16px;
      border-bottom:1px solid var(--border);
      background:linear-gradient(135deg, var(--surface-secondary), var(--surface));
      width:100%;
      min-width:auto;
    }

    .file-grid.list-view .file-icon-large{
      font-size:3rem;
    }

    .file-grid.list-view .card-badge{
      padding:4px 12px;
      font-size:11px;
    }

    .file-grid.list-view .card-content{
      flex-direction:column;
      padding:20px 24px;
      gap:12px;
      align-items:flex-start;
    }

    .file-grid.list-view .file-name{
      min-width:auto;
      width:100%;
      font-size:18px;
    }

    .file-grid.list-view .file-meta{
      flex-direction:column;
      gap:8px;
      width:100%;
    }

    .file-grid.list-view .card-actions{
      padding:16px 24px 20px;
      border-top:1px solid var(--border);
      background:var(--surface-secondary);
      width:100%;
      justify-content:center;
      flex-wrap:wrap;
    }

    .file-grid.list-view .btn{
      width:44px;
      height:44px;
    }

    .file-grid.list-view .btn-icon{
      font-size:16px;
    }
  }

  @media (max-width:480px){
    .file-grid{grid-template-columns:1fr}
    .card-actions{flex-direction:column;width:100%}
    .btn{width:100%;margin:4px 0}
    .btn-primary{width:100%;margin:8px 0}
    .btn-large{width:100%}
    .meta-item{flex-direction:column;gap:4px;text-align:center}
    .card-header{flex-direction:column;gap:12px;text-align:center}
    .card-badge{align-self:center}
  }

  /* Dark mode adjustments for better contrast */
  body[data-theme*="dark"] .file-card:hover{
    box-shadow:0 12px 32px rgba(0,0,0,0.3);
  }

  /* Print styles */
  @media print{
    .theme-switcher,
    .sort-controls,
    .card-actions,
    .provider-switcher{
      display:none !important;
    }

    .file-card{
      break-inside:avoid;
      box-shadow:none;
      border:1px solid #ccc;
    }
  }

/* Global Search Styles */
.global-search-container {
  display: flex;
  align-items: center;
  gap: 12px;
  background: var(--surface);
  border: 2px solid var(--border);
  border-radius: var(--border-radius-sm);
  padding: 12px 16px;
  margin: 20px 0;
  box-shadow: var(--shadow);
  transition: var(--transition);
  max-width: 600px;
}

.global-search-container:focus-within {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(77, 157, 255, 0.1);
}

.search-icon {
  font-size: 1.2rem;
  color: var(--text-secondary);
  flex-shrink: 0;
}

.global-search-input {
  flex: 1;
  border: none;
  outline: none;
  background: transparent;
  color: var(--text);
  font-size: 1rem;
  font-family: inherit;
  min-width: 200px;
}

.global-search-input::placeholder {
  color: var(--text-secondary);
}

.search-btn {
  background: var(--accent);
  color: white;
  border: none;
  border-radius: var(--border-radius-xs);
  padding: 10px 16px;
  font-weight: 500;
  cursor: pointer;
  transition: var(--transition);
  white-space: nowrap;
}

.search-btn:hover {
  background: #0056b3;
  transform: translateY(-1px);
}

.search-btn:active {
  transform: translateY(0);
}

@media (max-width: 768px) {
  .global-search-container {
    flex-direction: column;
    gap: 10px;
    padding: 16px;
  }

  .global-search-input {
    min-width: auto;
    width: 100%;
  }

  .search-btn {
    width: 100%;
    padding: 12px;
  }
}

/* Bulk Selection Styles */
.file-checkbox {
  width: 18px;
  height: 18px;
  cursor: pointer;
  margin-right: 10px;
}

.bulk-toolbar {
  position: fixed;
  bottom: 20px;
  left: 50%;
  transform: translateX(-50%);
  background: var(--surface);
  border: 2px solid var(--accent);
  border-radius: 12px;
  padding: 15px 25px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.3);
  display: none;
  align-items: center;
  gap: 15px;
  z-index: 1000;
  animation: slideUp 0.3s ease;
}

@keyframes slideUp {
  from { transform: translateX(-50%) translateY(100px); opacity: 0; }
  to { transform: translateX(-50%) translateY(0); opacity: 1; }
}

.bulk-toolbar.active { display: flex; }
.bulk-count { font-weight: bold; color: var(--accent); }

.bulk-action-btn {
  padding: 8px 16px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s;
}

.bulk-export-cdn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
.bulk-export-direct { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; }
.bulk-export-download { background: linear-gradient(135deg, #ff6a00 0%, #ee0979 100%); color: white; }
.bulk-export-both { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; }
.bulk-export-json { background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); color: white; }
.bulk-export-md { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; }
.bulk-delete-btn { background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%); color: white; }
.bulk-clear-btn { background: #6c757d; color: white; }

.bulk-action-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.2);
}

.select-all-container {
  display: flex;
  align-items: center;
  padding: 10px 15px;
  background: var(--surface-secondary);
  border-radius: 8px;
  margin-bottom: 15px;
}

.select-all-container label {
  margin-left: 8px;
  cursor: pointer;
  font-weight: 500;
}

/* AI Chat Widget Styles */
.ai-chat-widget {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 10000;
}

.ai-chat-toggle {
  padding: 12px 20px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  border-radius: 25px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 600;
  box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
  transition: all 0.3s;
}

.ai-chat-toggle:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
}

.ai-chat-panel {
  position: absolute;
  top: 60px;
  right: 0;
  width: 380px;
  max-width: calc(100vw - 40px);
  height: 500px;
  max-height: calc(100vh - 100px);
  background: var(--surface);
  border: 2px solid var(--accent);
  border-radius: 12px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.3);
  display: flex;
  flex-direction: column;
  animation: slideDown 0.3s ease;
}

.ai-chat-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 15px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border-radius: 10px 10px 0 0;
}

.ai-chat-title {
  font-weight: 600;
  font-size: 16px;
}

.ai-chat-close {
  background: transparent;
  border: none;
  color: white;
  font-size: 18px;
  cursor: pointer;
  padding: 0;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  transition: background 0.2s;
}

.ai-chat-close:hover {
  background: rgba(255,255,255,0.2);
}

.ai-chat-messages {
  flex: 1;
  overflow-y: auto;
  padding: 15px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.ai-message {
  padding: 12px 15px;
  border-radius: 12px;
  max-width: 85%;
  word-wrap: break-word;
}

.ai-message.ai-user {
  background: var(--accent);
  color: white;
  align-self: flex-end;
  margin-left: auto;
}

.ai-message.ai-assistant {
  background: var(--surface-secondary);
  color: var(--text);
  align-self: flex-start;
}

.ai-message.ai-error {
  background: var(--error);
  color: white;
  align-self: flex-start;
}

.ai-message.ai-tool-info {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  align-self: center;
  font-size: 12px;
  padding: 8px 12px;
  border-radius: 20px;
  margin: 8px 0;
}

.ai-status {
  font-size: 11px;
  color: var(--text-secondary);
  margin-top: 5px;
  text-align: center;
}

.ai-message-content {
  font-size: 14px;
  line-height: 1.6;
  word-wrap: break-word;
}

.ai-message-content ul,
.ai-message-content ol {
  margin: 8px 0;
  padding-left: 20px;
}

.ai-message-content li {
  margin: 4px 0;
}

.ai-chat-input-container {
  display: flex;
  gap: 8px;
  padding: 15px;
  border-top: 1px solid var(--border);
}

.ai-chat-input {
  flex: 1;
  padding: 10px 15px;
  border: 1px solid var(--border);
  border-radius: 20px;
  background: var(--surface-secondary);
  color: var(--text);
  font-size: 14px;
  outline: none;
  transition: border-color 0.2s;
}

.ai-chat-input:focus {
  border-color: var(--accent);
}

.ai-chat-send {
  padding: 10px 20px;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 20px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 600;
  transition: all 0.2s;
}

.ai-chat-send:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.2);
}

.ai-chat-send:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.ai-typing-indicator {
  display: inline-block;
  padding: 12px 15px;
  background: var(--surface-secondary);
  border-radius: 12px;
  align-self: flex-start;
}

.ai-typing-dots {
  display: flex;
  gap: 4px;
}

.ai-typing-dots span {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent);
  animation: typing 1.4s infinite;
}

.ai-typing-dots span:nth-child(2) {
  animation-delay: 0.2s;
}

.ai-typing-dots span:nth-child(3) {
  animation-delay: 0.4s;
}

@keyframes typing {
  0%, 60%, 100% { transform: translateY(0); }
  30% { transform: translateY(-10px); }
}

@keyframes slideDown {
  from { transform: translateY(-20px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}

@media (max-width: 768px) {
  .ai-chat-panel {
    width: calc(100vw - 40px);
    height: 60vh;
    top: 70px;
  }
  
  .ai-chat-widget {
    top: 10px;
    right: 10px;
  }
}

</style>
</head><body data-theme="${CONFIG.theme}">
  <div class="container">
    <header>
      <div class="header-content">
        <div class="logo-section">
          <div class="site-icon">${CONFIG.siteIcon}</div>
          <div class="title-section">
            <h1>${CONFIG.siteName}</h1>
            <div class="subtitle">Unified Multi-Cloud Storage Interface</div>
</div>
        </div>
        <div class="header-stats">
          <div class="stat-item">
            <span class="stat-icon">🔗</span>
            <span class="stat-text">${Object.keys(CONFIG.pathRouting).filter(k => k !== 'default').length} Providers</span>
          </div>
          <div class="stat-item">
            <span class="stat-icon">⚡</span>
            <span class="stat-text">Real-time</span>
          </div>
        </div>
      </div>
    </header>

    ${providerSwitcher}
    ${currentProviderInfo}
    ${globalSearchBox}
    ${mobileNotice}

    <div class="breadcrumb">
      <nav aria-label="Breadcrumb">
        <ol class="breadcrumb-list">
          <li class="breadcrumb-item">
            <a href="/" class="breadcrumb-link">🏠 Home</a>
          </li>
          ${breadcrumbs}
        </ol>
      </nav>
    </div>

    ${sortControls}

    ${selectAllCheckbox}
    ${emptyState || fileGrid}
    ${bulkToolbar}
    ${aiChatWidget}

    <div class="stats">
      <div class="stat">
        <span class="stat-icon">📁</span>
        <span id="folderCount">${folders.length} folders</span>
      </div>
      <div class="stat">
        <span class="stat-icon">📄</span>
        <span id="fileCount">${files.length} files</span>
      </div>
      <div class="stat">
        <span class="stat-icon">💾</span>
        <span id="totalSize">Total: ${formatSize(files.reduce((sum, f) => sum + f.size, 0))}</span>
      </div>
      <div class="stat">
        <span class="stat-icon">👁️</span>
        <span id="visibleCount">Showing: ${folders.length + files.length} items</span>
      </div>
      <div class="stat">
        <span class="stat-icon">🔄</span>
        <span>Strategy: ${CONFIG.routingStrategy}</span>
      </div>
    </div>

    <footer>
      <p>🌤️ Multi-Cloud Storage powered by Cloudflare Workers</p>
      <p>${Object.values(PROVIDERS).map((p) => `${p.icon} ${p.name}`).join(" • ")}</p>
      <div class="keyboard-shortcuts">
        <button class="shortcuts-toggle" onclick="toggleShortcutsHelp()">⌨️ Keyboard Shortcuts</button>
        <div class="shortcuts-panel" id="shortcutsPanel">
          <div class="shortcuts-content">
            <h3>⌨️ Keyboard Shortcuts</h3>
            <div class="shortcuts-grid">
              <div class="shortcut-item">
                <kbd>/</kbd>
                <span>Focus search</span>
              </div>
              <div class="shortcut-item">
                <kbd>Esc</kbd>
                <span>Clear search</span>
              </div>
              <div class="shortcut-item">
                <kbd>↑</kbd><kbd>↓</kbd>
                <span>Navigate files</span>
              </div>
              <div class="shortcut-item">
                <kbd>Enter</kbd>
                <span>Open/Preview</span>
              </div>
              <div class="shortcut-item">
                <kbd>?</kbd>
                <span>Toggle this help</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </footer>

    <div id="toastContainer"></div>
    <div class="global-loading" id="globalLoading">
      <div class="global-loading-bar" id="globalLoadingBar"></div>
    </div>
  </div>

<script>
  // Global variables for sorting and filtering
  let currentSortField = '${CONFIG.defaultSort.field}';
  let currentSortDirection = '${CONFIG.defaultSort.direction}';
  let currentTheme = '${CONFIG.theme}';
  let currentView = 'list'; // Default to list view
  let isCompactMode = false;
  let searchTerm = '';
  let selectedFileIndex = -1;

  // Theme configuration
  const themes = ${JSON.stringify(CONFIG.availableThemes)};

  // Detect if mobile device
  function isMobileDevice() {
    return window.innerWidth <= 768;
  }

  // Initialize on page load
  document.addEventListener('DOMContentLoaded', function() {
    // Load saved theme from localStorage
    const savedTheme = localStorage.getItem('cloudStorageTheme') || '${CONFIG.theme}';
    if (savedTheme !== currentTheme && themes[savedTheme]) {
      applyTheme(savedTheme);
    }

    // Load saved view preference or default to list on mobile, grid on desktop
    const savedView = localStorage.getItem('cloudStorageView');
    if (savedView) {
      currentView = savedView;
    } else {
      currentView = isMobileDevice() ? 'list' : 'list'; // Default to list for all
    }
    applyView(currentView);

    // Load compact mode preference
    const savedCompactMode = localStorage.getItem('cloudStorageCompactMode');
    if (savedCompactMode === 'true') {
      isCompactMode = true;
      const grid = document.getElementById('fileGrid');
      const btn = document.getElementById('compactViewBtn');
      if (grid) grid.classList.add('compact-mode');
      if (btn) btn.classList.add('active');
    }

    // Set initial controls
    document.getElementById('sortField').value = currentSortField;
    document.getElementById('sortDirection').value = currentSortDirection;
    document.getElementById('themeSelect').value = currentTheme;

    // Add event listeners
    document.getElementById('sortField').addEventListener('change', handleSort);
    document.getElementById('sortDirection').addEventListener('change', handleSort);
    document.getElementById('themeSelect').addEventListener('change', handleThemeChange);
    document.getElementById('fileSearch').addEventListener('input', handleSearch);

    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);

    // Initial sort
    performSort();
  });

  // Keyboard shortcuts handler
  function handleKeyboardShortcuts(e) {
    // Focus search on '/'
    if (e.key === '/' && document.activeElement !== document.getElementById('fileSearch')) {
      e.preventDefault();
      document.getElementById('fileSearch').focus();
      return;
    }

    // Clear search on Escape
    if (e.key === 'Escape') {
      if (document.getElementById('fileSearch').value) {
        clearSearch();
      } else if (document.getElementById('shortcutsPanel').classList.contains('show')) {
        toggleShortcutsHelp();
      }
      return;
    }

    // Toggle shortcuts help on '?'
    if (e.key === '?' && document.activeElement !== document.getElementById('fileSearch')) {
      e.preventDefault();
      toggleShortcutsHelp();
      return;
    }

    // Arrow key navigation
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      if (document.activeElement === document.getElementById('fileSearch')) return;
      
      e.preventDefault();
      const cards = Array.from(document.querySelectorAll('.file-card:not([style*="display: none"])'));
      if (cards.length === 0) return;

      if (e.key === 'ArrowDown') {
        selectedFileIndex = Math.min(selectedFileIndex + 1, cards.length - 1);
      } else {
        selectedFileIndex = Math.max(selectedFileIndex - 1, 0);
      }

      // Highlight selected card
      cards.forEach((card, index) => {
        if (index === selectedFileIndex) {
          card.style.outline = '3px solid var(--accent)';
          card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } else {
          card.style.outline = 'none';
        }
      });
      return;
    }

    // Open/preview on Enter
    if (e.key === 'Enter' && selectedFileIndex >= 0) {
      const cards = Array.from(document.querySelectorAll('.file-card:not([style*="display: none"])'));
      if (cards[selectedFileIndex]) {
        const previewBtn = cards[selectedFileIndex].querySelector('.btn-preview');
        const openBtn = cards[selectedFileIndex].querySelector('.btn-primary');
        if (previewBtn) {
          previewBtn.click();
        } else if (openBtn) {
          openBtn.click();
        }
      }
      return;
    }
  }

  // Toggle shortcuts help panel
  function toggleShortcutsHelp() {
    const panel = document.getElementById('shortcutsPanel');
    panel.classList.toggle('show');
  }

  // Toggle compact mode
  function toggleCompactMode() {
    isCompactMode = !isCompactMode;
    const grid = document.getElementById('fileGrid');
    const btn = document.getElementById('compactViewBtn');
    
    if (isCompactMode) {
      grid.classList.add('compact-mode');
      btn.classList.add('active');
      showToast('Compact mode enabled', 'success');
    } else {
      grid.classList.remove('compact-mode');
      btn.classList.remove('active');
      showToast('Compact mode disabled', 'success');
    }
    
    localStorage.setItem('cloudStorageCompactMode', isCompactMode);
  }

  function handleThemeChange() {
    const selectedTheme = document.getElementById('themeSelect').value;
    if (themes[selectedTheme]) {
      applyTheme(selectedTheme);
      localStorage.setItem('cloudStorageTheme', selectedTheme);
      showToast(\`Theme changed to \${themes[selectedTheme].name}!\`, 'success');
    }
  }

  function applyTheme(themeKey) {
    const theme = themes[themeKey];
    if (!theme) return;

    currentTheme = themeKey;
    document.body.setAttribute('data-theme', themeKey);

    // Update CSS custom properties
    const root = document.documentElement;
    root.style.setProperty('--bg-gradient', theme.background);
    root.style.setProperty('--surface', theme.surface);
    root.style.setProperty('--surface-secondary', theme.surfaceSecondary);
    root.style.setProperty('--text', theme.text);
    root.style.setProperty('--text-secondary', theme.textSecondary);
    root.style.setProperty('--accent', theme.accent);
    root.style.setProperty('--accent-secondary', theme.accentSecondary);
    root.style.setProperty('--border', theme.border);
    root.style.setProperty('--success', theme.success);
    root.style.setProperty('--error', theme.error);
    root.style.setProperty('--warning', theme.warning);

    // Update theme selector
    document.getElementById('themeSelect').value = themeKey;
  }

  function switchView(viewType) {
    currentView = viewType;
    applyView(viewType);
    localStorage.setItem('cloudStorageView', viewType);
    showToast(\`Switched to \${viewType} view\`, 'success');
  }

  function applyView(viewType) {
    const grid = document.getElementById('fileGrid');
    const gridBtn = document.getElementById('gridViewBtn');
    const listBtn = document.getElementById('listViewBtn');
    const headers = document.getElementById('listViewHeaders');
    
    if (!grid || !gridBtn || !listBtn) return;

    if (viewType === 'list') {
      grid.classList.add('list-view');
      listBtn.classList.add('active');
      gridBtn.classList.remove('active');
      if (headers) headers.style.display = 'flex';
      updateSortIndicators();
    } else {
      grid.classList.remove('list-view');
      gridBtn.classList.add('active');
      listBtn.classList.remove('active');
      if (headers) headers.style.display = 'none';
    }
  }

  // Sort by column header click
  function sortByColumn(field) {
    if (currentSortField === field) {
      // Toggle direction if same field
      currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      // New field, default to ascending
      currentSortField = field;
      currentSortDirection = 'asc';
    }
    
    // Update dropdowns to match
    document.getElementById('sortField').value = currentSortField;
    document.getElementById('sortDirection').value = currentSortDirection;
    
    updateSortIndicators();
    performSort();
  }

  // Update sort indicators on column headers
  function updateSortIndicators() {
    ['name', 'size', 'date'].forEach(field => {
      const indicator = document.getElementById(\`sort-\${field}\`);
      if (indicator) {
        if (field === currentSortField) {
          indicator.classList.add('active');
          indicator.textContent = currentSortDirection === 'asc' ? '↑' : '↓';
        } else {
          indicator.classList.remove('active');
          indicator.textContent = '';
        }
      }
    });
  }

  function handleSort() {
    currentSortField = document.getElementById('sortField').value;
    currentSortDirection = document.getElementById('sortDirection').value;
    updateSortIndicators();
    performSort();
  }

  function handleSearch() {
    searchTerm = document.getElementById('fileSearch').value.toLowerCase();
    performSort();
  }

  function clearSearch() {
    document.getElementById('fileSearch').value = '';
    searchTerm = '';
    performSort();
  }

  function performSort() {
    const grid = document.getElementById('fileGrid');
    if (!grid) return;

    const cards = Array.from(grid.children);

    // Filter cards based on search
    let filteredCards = cards.filter(card => {
      if (!searchTerm) return true;
      const name = card.dataset.name || '';
      return name.includes(searchTerm);
    });

    // Sort cards
    filteredCards.sort((a, b) => {
      let aValue, bValue;

      switch (currentSortField) {
        case 'name':
          aValue = (a.dataset.name || '').toLowerCase();
          bValue = (b.dataset.name || '').toLowerCase();
          break;
        case 'size':
          aValue = parseInt(a.dataset.size) || 0;
          bValue = parseInt(b.dataset.size) || 0;
          break;
        case 'date':
          aValue = parseInt(a.dataset.date) || 0;
          bValue = parseInt(b.dataset.date) || 0;
          break;
        default:
          return 0;
      }

      // Folders always come first
      if (a.dataset.type === 'folder' && b.dataset.type === 'file') return -1;
      if (a.dataset.type === 'file' && b.dataset.type === 'folder') return 1;

      if (currentSortDirection === 'asc') {
        return aValue > bValue ? 1 : aValue < bValue ? -1 : 0;
      } else {
        return aValue < bValue ? 1 : aValue > bValue ? -1 : 0;
      }
    });

    // Update real-time stats
    updateStats(filteredCards);

    // Clear and re-append sorted cards with animation
    grid.innerHTML = '';
    filteredCards.forEach((card, index) => {
      card.style.opacity = '0';
      card.style.transform = 'translateY(20px)';
      grid.appendChild(card);

      // Stagger animation
      setTimeout(() => {
        card.style.transition = 'all 0.3s ease';
        card.style.opacity = '1';
        card.style.transform = 'translateY(0)';
      }, index * 50);
    });
  }

  // Update stats in real-time
  function updateStats(cards) {
    const folders = cards.filter(c => c.dataset.type === 'folder');
    const files = cards.filter(c => c.dataset.type === 'file');
    const totalSize = files.reduce((sum, f) => sum + parseInt(f.dataset.size || 0), 0);

    const folderCount = document.getElementById('folderCount');
    const fileCount = document.getElementById('fileCount');
    const totalSizeEl = document.getElementById('totalSize');
    const visibleCount = document.getElementById('visibleCount');

    if (folderCount) folderCount.textContent = \`\${folders.length} folders\`;
    if (fileCount) fileCount.textContent = \`\${files.length} files\`;
    if (totalSizeEl) totalSizeEl.textContent = \`Total: \${formatSizeJS(totalSize)}\`;
    if (visibleCount) visibleCount.textContent = \`Showing: \${cards.length} items\`;
  }

  // Format size in JavaScript
  function formatSizeJS(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function goBack() {
    window.history.back();
  }

  async function downloadFile(fileKey, element) {
    const originalHTML = element ? element.innerHTML : null;
    if (element) {
      element.innerHTML = '<div class="loading-spinner"></div>';
      element.disabled = true;
    }
    
    try {
      // Create a temporary link to trigger download
      const link = document.createElement('a');
      link.href = '/' + fileKey + '?download';
      link.style.display = 'none';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      if (element) {
        // Show success checkmark
        element.innerHTML = '<span class="btn-icon">✅</span>';
        showToast('Download started!', 'success');
        
        // Restore original button after delay
        setTimeout(() => {
          element.innerHTML = originalHTML;
          element.disabled = false;
        }, 2000);
      }
    } catch (err) {
      console.error('Download failed:', err);
      if (element) {
        element.innerHTML = originalHTML;
        element.disabled = false;
        showToast('Download failed: ' + err.message, 'error');
      }
    }
  }

  async function previewFile(fileKey, element) {
    const originalHTML = element ? element.innerHTML : null;
    if (element) {
      element.innerHTML = '<div class="loading-spinner"></div>';
      element.disabled = true;
    }
    
    try {
      // Open preview in new tab
      const previewWindow = window.open('/' + fileKey + '?preview', '_blank');
      
      if (element) {
        // Show success checkmark
        element.innerHTML = '<span class="btn-icon">✅</span>';
        showToast('Preview opened in new tab!', 'success');
        
        // Restore original button after delay
        setTimeout(() => {
          element.innerHTML = originalHTML;
          element.disabled = false;
        }, 2000);
      }
    } catch (err) {
      console.error('Preview failed:', err);
      if (element) {
        element.innerHTML = originalHTML;
        element.disabled = false;
        showToast('Preview failed: ' + err.message, 'error');
      }
    }
  }

  function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = \`toast \${type}\`;
    toast.innerHTML = \`<span>\${message}</span><button class="toast-close" onclick="this.parentElement.remove()">×</button>\`;

    toastContainer.appendChild(toast);

    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);

    // Auto remove after 5 seconds
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, 5000);
  }

  // Global loading functions
  function showGlobalLoading() {
    const loading = document.getElementById('globalLoading');
    const loadingBar = document.getElementById('globalLoadingBar');
    if (loading && loadingBar) {
      loading.classList.add('show');
      loadingBar.style.width = '30%';
    }
  }

  function hideGlobalLoading() {
    const loading = document.getElementById('globalLoading');
    const loadingBar = document.getElementById('globalLoadingBar');
    if (loading && loadingBar) {
      loadingBar.style.width = '100%';
      setTimeout(() => {
        loading.classList.remove('show');
        setTimeout(() => {
          loadingBar.style.width = '0%';
        }, 300);
      }, 300);
    }
  }

  function copyToClipboard(text, element, skipLoading = false) {
    if (!navigator.clipboard) {
      showToast('Clipboard API not available. Please copy manually.', 'error');
      return;
    }

    const originalHTML = element.innerHTML;
    
    if (!skipLoading) {
      element.innerHTML = '<div class="loading-spinner"></div>';
      element.disabled = true;
    }

    navigator.clipboard.writeText(text).then(() => {
      element.innerHTML = '<span class="btn-icon">✅</span>';
      showToast('Link copied to clipboard!', 'success');
      setTimeout(() => {
        element.innerHTML = originalHTML;
        element.disabled = false;
      }, 2000);
    }).catch(err => {
      console.error('Failed to copy text: ', err);
      showToast('Failed to copy link.', 'error');
      element.innerHTML = originalHTML;
      element.disabled = false;
    });
  }

  async function generateShareLink(fileKey, element, useCDN) {
    const originalHTML = element.innerHTML;
    element.innerHTML = '<div class="loading-spinner"></div>';
    element.disabled = true;
    
    try {
      const cdnParam = useCDN ? '&cdn=true' : '';
      const response = await fetch('/' + fileKey + '?share=true' + cdnParam);
      const data = await response.json();
      
      if (response.ok && data.success) {
        const linkType = useCDN ? 'CDN' : 'Direct S3';
        const toastMsg = useCDN 
          ? '🚀 CDN link copied! (Fast for repeated viewing)' 
          : '🔗 Direct S3 link copied! (Best compatibility)';
        
        navigator.clipboard.writeText(data.url).then(() => {
          element.innerHTML = '<span class="btn-icon">✅</span>';
          showToast(toastMsg, 'success');
          setTimeout(() => {
            element.innerHTML = originalHTML;
            element.disabled = false;
          }, 2000);
        }).catch(err => {
          console.error('Failed to copy text: ', err);
          showToast('Failed to copy link.', 'error');
          element.innerHTML = originalHTML;
          element.disabled = false;
        });
      } else {
        throw new Error(data.error || 'Failed to generate link');
      }
    } catch (err) {
      console.error('Failed to generate share link:', err);
      showToast('Failed to generate share link: ' + err.message, 'error');
      element.innerHTML = originalHTML;
      element.disabled = false;
    }
  }

  async function deleteFile(fileKey, element) {
    if (!confirm('Are you sure you want to delete this file?\\nThis action cannot be undone.')) {
      return;
    }
    
    const card = element.closest('.file-card');
    const originalHTML = element.innerHTML;
    element.innerHTML = '<div class="loading-spinner"></div>';
    element.disabled = true;
    
    try {
      const response = await fetch('/' + fileKey, {
        method: 'DELETE'
      });
      
      const data = await response.json();
      
      if (response.ok && data.success) {
        // Show success checkmark on the delete button
        element.innerHTML = '<span class="btn-icon">✅</span>';
        showToast('File deleted successfully!', 'success');
        
        // Add smooth fade-out animation to the card
        card.style.transition = 'all 0.3s ease';
        card.style.opacity = '0';
        card.style.transform = 'scale(0.95) translateY(-10px)';
        
        // Remove card after animation completes
        setTimeout(() => {
          card.remove();
        }, 300);
      } else {
        throw new Error(data.error || 'Failed to delete file');
      }
    } catch (err) {
      console.error('Failed to delete file:', err);
      showToast('Error: ' + err.message, 'error');
      element.innerHTML = originalHTML;
      element.disabled = false;
    }
  }

  // Global search function
  function performGlobalSearch() {
    const searchInput = document.getElementById('global-search-input');
    const query = searchInput.value.trim();

    if (query.length < 2) {
      showToast('Please enter at least 2 characters to search', 'warning');
      searchInput.focus();
      return;
    }

    // Redirect to search page
    window.location.href = '/?search=' + encodeURIComponent(query);
  }

  // Bulk Selection Functions
  let selectedFiles = new Set();

  function updateSelectionUI() {
    const count = selectedFiles.size;
    const selectedCountElem = document.getElementById('selected-count');
    const bulkCountElem = document.getElementById('bulk-count');
    if (selectedCountElem) selectedCountElem.textContent = count;
    if (bulkCountElem) bulkCountElem.textContent = count;

    const toolbar = document.getElementById('bulk-toolbar');
    if (toolbar) {
      toolbar.classList.toggle('active', count > 0);
    }

    const selectAllCheckbox = document.getElementById('select-all-checkbox');
    const allFileCheckboxes = document.querySelectorAll('.file-checkbox');
    if (selectAllCheckbox && allFileCheckboxes.length > 0) {
      selectAllCheckbox.checked = count === allFileCheckboxes.length;
      selectAllCheckbox.indeterminate = count > 0 && count < allFileCheckboxes.length;
    }
  }

  function toggleSelectAll(checkbox) {
    selectedFiles.clear();
    document.querySelectorAll('.file-checkbox').forEach(cb => {
      cb.checked = checkbox.checked;
      if (checkbox.checked) {
        selectedFiles.add(cb.dataset.provider + ':' + cb.dataset.path);
      }
    });
    updateSelectionUI();
  }

  // Initialize checkbox event listeners
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.file-checkbox').forEach(checkbox => {
      checkbox.addEventListener('change', (e) => {
        const key = e.target.dataset.provider + ':' + e.target.dataset.path;
        if (e.target.checked) {
          selectedFiles.add(key);
        } else {
          selectedFiles.delete(key);
        }
        updateSelectionUI();
      });
    });
  });

  function clearSelection() {
    selectedFiles.clear();
    document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = false);
    const selectAllCheckbox = document.getElementById('select-all-checkbox');
    if (selectAllCheckbox) selectAllCheckbox.checked = false;
    updateSelectionUI();
  }

  async function bulkExport(exportType) {
    if (selectedFiles.size === 0) {
      showToast('❌ No files selected', 'error');
      return;
    }

    const filesParam = Array.from(selectedFiles).join(',');
    const exportUrl = window.location.origin + window.location.pathname + '?bulkExport=' + exportType + '&files=' + encodeURIComponent(filesParam);

    try {
      showToast('⏳ Generating links...', 'info');
      const response = await fetch(exportUrl);
      if (!response.ok) throw new Error('Export failed');

      const content = await response.text();
      await navigator.clipboard.writeText(content);
      showToast('✅ ' + selectedFiles.size + ' links copied to clipboard!', 'success');

      const blob = new Blob([content], { type: response.headers.get('content-type') });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'exported-links-' + Date.now() + '.' + (exportType === 'json' ? 'json' : exportType === 'markdown' ? 'md' : 'txt');
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      showToast('❌ Export failed: ' + error.message, 'error');
    }
  }

  async function bulkDeleteFiles() {
    if (selectedFiles.size === 0) {
      showToast('❌ No files selected', 'error');
      return;
    }

    const fileCount = selectedFiles.size;
    const confirmMsg = 'Are you sure you want to delete ' + fileCount + ' file(s)? This action cannot be undone!';
    
    if (!confirm(confirmMsg)) {
      return;
    }

    const filesParam = Array.from(selectedFiles).join(',');
    const deleteUrl = window.location.origin + window.location.pathname + '?bulkDelete=true&files=' + encodeURIComponent(filesParam);

    try {
      showToast('⏳ Deleting ' + fileCount + ' files...', 'info');
      const response = await fetch(deleteUrl, { method: 'GET' });
      
      if (!response.ok) {
        throw new Error('Bulk delete failed');
      }

      const result = await response.json();
      
      if (result.success) {
        showToast('✅ Deleted ' + result.deleted + ' of ' + result.total + ' files!', 'success');
        
        // Show errors if any
        if (result.failed > 0) {
          const failedFiles = result.results.filter(r => !r.success).map(r => r.fileName).join(', ');
          setTimeout(() => {
            showToast('⚠️ Failed to delete: ' + failedFiles, 'warning');
          }, 2000);
        }
        
        // Clear selection and reload page after a short delay
        setTimeout(() => {
          clearSelection();
          location.reload();
        }, 3000);
      } else {
        throw new Error(result.error || 'Delete failed');
      }
    } catch (error) {
      showToast('❌ Delete failed: ' + error.message, 'error');
    }
  }

  // AI Chat Functions
  function toggleAIChat() {
    const panel = document.getElementById('aiChatPanel');
    if (panel) {
      panel.style.display = panel.style.display === 'none' ? 'flex' : 'none';
      if (panel.style.display === 'flex') {
        document.getElementById('aiChatInput').focus();
      }
    }
  }

  function handleAIChatKey(event) {
    if (event.key === 'Enter') {
      sendAIMessage();
    }
  }

  // Store conversation history for agentic reasoning
  let conversationHistory = [];

  async function sendAIMessage() {
    const input = document.getElementById('aiChatInput');
    const messagesContainer = document.getElementById('aiChatMessages');
    const message = input.value.trim();

    if (!message) return;

    // Add user message to chat
    addAIChatMessage(message, 'user');
    input.value = '';

    // Add to conversation history
    conversationHistory.push({ role: 'user', content: message });

    // Show typing indicator with agentic status
    const typingIndicator = document.createElement('div');
    typingIndicator.className = 'ai-typing-indicator';
    typingIndicator.innerHTML = '<div class="ai-typing-dots"><span></span><span></span><span></span></div><div class="ai-status">🤖 Agent thinking...</div>';
    messagesContainer.appendChild(typingIndicator);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;

    // Gather file context
    const fileContext = gatherFileContext();

    try {
      const response = await fetch(window.location.origin + window.location.pathname + '?aiChat=true', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          message: message,
          context: fileContext,
          conversationHistory: conversationHistory.slice(-10) // Keep last 10 messages for context
        })
      });

      // Remove typing indicator
      messagesContainer.removeChild(typingIndicator);

      const data = await response.json();

      if (data.success) {
        // Add assistant response to history
        conversationHistory.push({ role: 'assistant', content: data.message });
        
        // Show agent activity if tools were used
        if (data.agentic && data.toolCalls && data.toolCalls.length > 0) {
          const toolSummary = '🔧 Agent used ' + data.toolCalls.length + ' tool(s) in ' + data.iterations + ' step(s)';
          addAIChatMessage(toolSummary, 'tool-info');
        }
        
        addAIChatMessage(data.message, 'assistant');
      } else {
        // Show detailed error info
        const errorMessage = data.error || data.fallback || 'AI request failed';
        console.error('[AI Chat Error]', data);
        addAIChatMessage(errorMessage, 'error');
        if (data.errorDetails) {
          console.error('[AI Chat Error Details]', data.errorDetails);
        }
      }
    } catch (error) {
      // Remove typing indicator
      if (typingIndicator.parentNode) {
        messagesContainer.removeChild(typingIndicator);
      }
      console.error('[AI Chat Exception]', error);
      addAIChatMessage('Sorry, I encountered an error: ' + error.message, 'error');
    }
  }

  function addAIChatMessage(content, type) {
    const messagesContainer = document.getElementById('aiChatMessages');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'ai-message ai-' + type;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'ai-message-content';
    
    // Simple HTML escaping and line break preservation
    let formattedContent = content
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .split('\\n').join('<br>');
    
    contentDiv.innerHTML = formattedContent;
    
    messageDiv.appendChild(contentDiv);
    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function gatherFileContext() {
    const files = Array.from(document.querySelectorAll('.file-card[data-type="file"]'));
    const folders = Array.from(document.querySelectorAll('.file-card[data-type="folder"]'));
    
    return {
      currentPath: window.location.pathname,
      fileCount: files.length,
      folderCount: folders.length,
      files: files.slice(0, 20).map(file => {
        const sizeBytes = parseInt(file.dataset.size) || 0;
        const sizeFormatted = formatSizeJS(sizeBytes);
        return {
          name: file.dataset.name,
          sizeBytes: sizeBytes,
          sizeFormatted: sizeFormatted,
          provider: file.dataset.provider
        };
      }),
      selectedFiles: selectedFiles ? selectedFiles.size : 0
    };
  }

</script>
</body></html>`;
}


function getLoginPage() {
  const authType = CONFIG.authMode === "username" ? "username and password" : "password";
  const showUsername = CONFIG.authMode === "username";
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Login - ${CONFIG.siteName}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 20px;
    }
    
    .login-container {
      background: #ffffff;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      padding: 48px 40px;
      width: 100%;
      max-width: 420px;
      animation: slideUp 0.5s ease;
    }
    
    @keyframes slideUp {
      from {
        opacity: 0;
        transform: translateY(30px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    
    .login-header {
      text-align: center;
      margin-bottom: 32px;
    }
    
    .login-icon {
      font-size: 48px;
      margin-bottom: 16px;
    }
    
    h1 {
      color: #2c3e50;
      font-size: 28px;
      font-weight: 700;
      margin-bottom: 8px;
    }
    
    .login-subtitle {
      color: #6c757d;
      font-size: 14px;
    }
    
    .form-group {
      margin-bottom: 20px;
    }
    
    label {
      display: block;
      color: #2c3e50;
      font-size: 14px;
      font-weight: 600;
      margin-bottom: 8px;
    }
    
    input {
      width: 100%;
      padding: 14px 16px;
      border: 2px solid #e1e8ed;
      border-radius: 8px;
      font-size: 15px;
      transition: all 0.3s ease;
      background: #f8f9fa;
    }
    
    input:focus {
      outline: none;
      border-color: #667eea;
      background: #ffffff;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    
    .btn-login {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
      margin-top: 24px;
    }
    
    .btn-login:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
    }
    
    .btn-login:active {
      transform: translateY(0);
    }
    
    .info-text {
      text-align: center;
      color: #6c757d;
      font-size: 13px;
      margin-top: 24px;
    }
    
    .security-badge {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      margin-top: 24px;
      padding: 12px;
      background: #f8f9fa;
      border-radius: 8px;
      color: #6c757d;
      font-size: 12px;
    }
    
    .error-message {
      background: #fee;
      color: #c33;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 20px;
      text-align: center;
      font-size: 14px;
      display: none;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-header">
      <div class="login-icon">${CONFIG.siteIcon}</div>
      <h1>Welcome Back</h1>
      <p class="login-subtitle">Sign in to access ${CONFIG.siteName}</p>
    </div>
    
    <div id="error-message" class="error-message"></div>
    
    <form id="loginForm">
      ${showUsername ? `
      <div class="form-group">
        <label for="username">👤 Username</label>
        <input 
          type="text" 
          id="username" 
          name="username" 
          placeholder="Enter your username"
          autocomplete="username"
          required
        />
      </div>
      ` : ''}
      
      <div class="form-group">
        <label for="password">🔐 Password</label>
        <input 
          type="password" 
          id="password" 
          name="password" 
          placeholder="Enter your password"
          autocomplete="current-password"
          required
        />
      </div>
      
      <button type="submit" class="btn-login">
        Sign In
      </button>
    </form>
    
    <div class="security-badge">
      <span>🔒</span>
      <span>Secured with WebDAV Basic Authentication</span>
    </div>
    
    <p class="info-text">
      Multi-Cloud S3 Storage Access
    </p>
  </div>
  
  <script>
    document.getElementById('loginForm').addEventListener('submit', function(e) {
      e.preventDefault();
      
      const username = ${showUsername ? "document.getElementById('username').value" : "'user'"};
      const password = document.getElementById('password').value;
      
      // Create Basic Auth header
      const credentials = btoa(username + ':' + password);
      
      // Make request with Basic Auth
      fetch(window.location.href, {
        method: 'GET',
        headers: {
          'Authorization': 'Basic ' + credentials
        }
      })
      .then(response => {
        if (response.ok) {
          // Store credentials for subsequent requests
          sessionStorage.setItem('authCredentials', credentials);
          window.location.reload();
        } else {
          const errorMsg = document.getElementById('error-message');
          errorMsg.style.display = 'block';
          errorMsg.textContent = '❌ Invalid ${authType}. Please try again.';
        }
      })
      .catch(error => {
        const errorMsg = document.getElementById('error-message');
        errorMsg.style.display = 'block';
        errorMsg.textContent = '❌ Authentication failed. Please try again.';
      });
    });
    
    // Check if already authenticated
    const stored = sessionStorage.getItem('authCredentials');
    if (stored) {
      fetch(window.location.href, {
        method: 'GET',
        headers: {
          'Authorization': 'Basic ' + stored
        }
      })
      .then(response => {
        if (response.ok) {
          window.location.reload();
        }
      });
    }
  </script>
</body>
</html>`;
}

function getErrorPage(message) {
  // ✅ IMPROVEMENT #7: User-friendly error messages
  const friendlyErrors = {
    'AccessDenied': {
      icon: '🔒',
      title: 'Access Denied',
      msg: 'You don\'t have permission to access this file. Please check your S3 bucket permissions or authentication credentials.',
      action: 'Contact your administrator if you believe this is an error.'
    },
    'NoSuchKey': {
      icon: '📭',
      title: 'File Not Found',
      msg: 'The requested file doesn\'t exist in the storage bucket. It may have been deleted or moved.',
      action: 'Go back and try browsing to find the file you\'re looking for.'
    },
    'NoSuchBucket': {
      icon: '🪣',
      title: 'Bucket Not Found',
      msg: 'The storage bucket doesn\'t exist. Please check your Worker environment configuration.',
      action: 'Verify your S3_BUCKET_NAME environment variable is set correctly.'
    },
    'SlowDown': {
      icon: '⏸️',
      title: 'Too Many Requests',
      msg: 'You\'re making requests too quickly. Please wait a moment before trying again.',
      action: 'Wait 10-30 seconds and refresh the page.'
    },
    'NetworkingError': {
      icon: '🌐',
      title: 'Network Error',
      msg: 'Unable to connect to the storage service. Please check your internet connection.',
      action: 'Refresh the page or try again in a few moments.'
    },
    'Timeout': {
      icon: '⏱️',
      title: 'Request Timeout',
      msg: 'The request took too long to complete. This might be due to a large file or slow network.',
      action: 'Try again or use a smaller file.'
    },
    'InvalidAccessKeyId': {
      icon: '🔑',
      title: 'Invalid Credentials',
      msg: 'The access credentials are invalid or have expired.',
      action: 'Check your ACCESS_KEY_ID and SECRET_ACCESS_KEY environment variables.'
    }
  };
  
  // Find matching error
  let errorInfo = null;
  for (const [key, info] of Object.entries(friendlyErrors)) {
    if (message.includes(key)) {
      errorInfo = info;
      break;
    }
  }
  
  // Use friendly error if found, otherwise show generic error
  const icon = errorInfo?.icon || '⚠️';
  const title = errorInfo?.title || 'Multi-Cloud Error';
  const friendlyMsg = errorInfo?.msg || 'An unexpected error occurred.';
  const action = errorInfo?.action || 'Please try again or contact support.';
  const technicalDetails = message.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>Error - ${CONFIG.siteName}</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#1a1a1a;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:20px}.container{text-align:center;background:#252525;padding:40px;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.3);max-width:600px;width:100%}.icon{font-size:64px;margin-bottom:20px}h1{color:#ff6b6b;margin-bottom:20px;font-size:24px}.friendly-msg{margin-bottom:20px;color:#e0e0e0;font-size:16px;line-height:1.6}.action-msg{margin-bottom:30px;padding:15px;background:#2a2a2a;border-left:4px solid #4d9fff;border-radius:6px;color:#4d9fff;font-size:14px;text-align:left}.technical-details{margin-top:30px;padding-top:20px;border-top:1px solid #444}.details-toggle{color:#888;font-size:12px;cursor:pointer;margin-bottom:10px;user-select:none}.details-toggle:hover{color:#aaa}.technical{display:none;margin-top:10px;word-break:break-word;text-align:left;background:#111;padding:15px;border-radius:6px;font-family:monospace;white-space:pre-wrap;font-size:11px;color:#888}.show-details .technical{display:block}a{color:#4d9fff;text-decoration:none;padding:12px 24px;background:#333;border-radius:6px;display:inline-block;transition:background .2s;margin:5px}a:hover{background:#444}</style></head><body><div class="container"><div class="icon">${icon}</div><h1>${title}</h1><p class="friendly-msg">${friendlyMsg}</p><div class="action-msg"><strong>💡 What to do:</strong><br>${action}</div><a href="/">← Back to Home</a><a href="javascript:location.reload()">🔄 Retry</a><div class="technical-details"><div class="details-toggle" onclick="this.parentElement.classList.toggle('show-details')">▶ Show Technical Details</div><p class="technical">${technicalDetails}</p></div></div></body></html>`;
}

// Helper function to check if files can be previewed
function isPreviewable(fileName) {
  const ext = fileName.split('.').pop().toLowerCase();
  return ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'mp4', 'webm', 'ogg', 'mp3', 'wav', 'pdf', 'txt', 'json', 'xml', 'html', 'css', 'js'].includes(ext);
}

// Main search handler that orchestrates parallel search across all providers
async function handleGlobalSearch(query, env, request) {
  if (!query || query.trim().length < 2) {
    return new Response(getSearchResultsPage(query, [], [], 'Search query must be at least 2 characters long.', request), {
      headers: { 'Content-Type': 'text/html' }
    });
  }

  const trimmedQuery = query.trim().toLowerCase();
  const providers = Object.keys(PROVIDERS);
  const searchPromises = providers.map(provider => {
    const providerConfig = getProviderConfig(env, provider);
    return providerConfig ? searchInProvider(providerConfig, trimmedQuery) : [];
  });
  const results = await Promise.allSettled(searchPromises);

  const allResults = [];
  const errors = [];

  results.forEach((result, index) => {
    const provider = providers[index];
    if (result.status === 'fulfilled') {
      allResults.push(...result.value);
    } else {
      errors.push({ provider: PROVIDERS[provider].name, error: result.reason.message });
    }
  });

  // Sort results: exact matches first, then by relevance
  allResults.sort((a, b) => {
    const aExact = a.name.toLowerCase() === trimmedQuery;
    const bExact = b.name.toLowerCase() === trimmedQuery;

    if (aExact && !bExact) return -1;
    if (!aExact && bExact) return 1;

    // For partial matches, prefer shorter names (likely more relevant)
    return a.name.length - b.name.length;
  });

  return new Response(getSearchResultsPage(query, allResults, errors, request), {
    headers: { 'Content-Type': 'text/html' }
  });
}

// Recursively searches through folders in a specific cloud provider
async function searchInProvider(providerConfig, searchQuery, prefix = "", results = []) {
  try {
    // Call listObjects and handle the response properly
    const listResult = await listObjects(providerConfig, prefix);

    // Ensure we have valid arrays to work with
    const folders = Array.isArray(listResult.folders) ? listResult.folders : [];
    const files = Array.isArray(listResult.files) ? listResult.files : [];

    // Add matching files
    files.forEach(file => {
      if (file.name && file.name.toLowerCase().includes(searchQuery)) {
        // Calculate folder path from full path
        const pathParts = file.key.split('/');
        const folderPath = pathParts.length > 1 ? pathParts.slice(0, -1).join('/') + '/' : '';
        results.push({
          ...file,
          fullPath: file.key,
          folderPath: folderPath || '/'
        });
      }
    });

    // Recursively search subfolders (with depth limit to prevent infinite loops)
    const MAX_DEPTH = 10;
    const currentDepth = prefix.split('/').filter(p => p).length;

    if (currentDepth < MAX_DEPTH && folders.length > 0) {
      // Search up to 5 folders in parallel to avoid overwhelming the API
      const folderBatches = [];
      for (let i = 0; i < folders.length; i += 5) {
        folderBatches.push(folders.slice(i, i + 5));
      }

      for (const batch of folderBatches) {
        const folderPromises = batch.map(folder => {
          // Use the prefix from the folder object directly
          let folderPrefix = folder.prefix || "";

          // Strip routing prefixes (impossible/, wasabi/, r2/, oci/)
          const routingPrefixes = Object.keys(CONFIG.pathRouting).filter(k => k !== 'default');
          for (const routePrefix of routingPrefixes) {
            if (folderPrefix.startsWith(routePrefix)) {
              folderPrefix = folderPrefix.substring(routePrefix.length);
              break;
            }
          }

          return searchInProvider(providerConfig, searchQuery, folderPrefix, results);
        });

        await Promise.all(folderPromises);
      }
    }

    return results;
  } catch (error) {
    console.error(`Search error in ${providerConfig.name}:`, error);
    // Return partial results instead of throwing
    // This allows other providers to continue searching
    return results;
  }
}

// Generates the beautiful search results HTML page
function getSearchResultsPage(query, results, errors, request) {
  const baseUrl = new URL(request.url).origin;

  const formatSize = (bytes) => {
    if (!bytes) return 'Unknown';
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatDate = (date) => {
    if (!date) return 'Unknown';
    return new Date(date).toLocaleDateString() + ' ' + new Date(date).toLocaleTimeString();
  };

  const errorBanner = errors.length > 0 ? `
    <div class="error-banner">
      <div class="error-icon">⚠️</div>
      <div class="error-content">
        <h3>Some providers failed to search</h3>
        <ul class="error-list">
          ${errors.map(error => `<li><strong>${error.provider}:</strong> ${error.error}</li>`).join('')}
        </ul>
      </div>
    </div>
  ` : '';

  const stats = `
    <div class="search-stats">
      <div class="stat-item">
        <span class="stat-icon">🔍</span>
        <span class="stat-text">Searched: "${query}"</span>
      </div>
      <div class="stat-item">
        <span class="stat-icon">📁</span>
        <span class="stat-text">${results.length} results</span>
      </div>
      <div class="stat-item">
        <span class="stat-icon">☁️</span>
        <span class="stat-text">${Object.keys(PROVIDERS).length} providers</span>
      </div>
    </div>
  `;

  const resultCards = results.length > 0 ? results.map(result => {
    const folderUrl = result.folderPath === 'Root' ? '/' : `/${result.folderPath}`;
    const sizeInGB = result.size / (1024 * 1024 * 1024);
    const recommendCDN = sizeInGB < 1;
    const cdnClass = recommendCDN ? 'action-btn cdn-btn' : 'action-btn cdn-btn btn-dimmed';
    const directClass = recommendCDN ? 'action-btn direct-btn btn-dimmed' : 'action-btn direct-btn btn-recommended';
    const cdnBadge = recommendCDN ? ' ✨' : '';
    const directBadge = recommendCDN ? '' : ' ✨';

    return `
      <div class="search-result-card">
        <div class="result-header">
          <div class="file-info">
            <div class="file-name">${result.name}</div>
            <div class="file-meta">
              <span class="file-size">📏 ${formatSize(result.size)}</span>
              <span class="file-date">📅 ${formatDate(result.lastModified)}</span>
            </div>
          </div>
          <div class="provider-badge">
            <span class="provider-icon">${result.providerIcon}</span>
            <span class="provider-name">${result.providerName}</span>
          </div>
        </div>

        <div class="folder-path">
          <span class="folder-icon">📂</span>
          <span class="folder-text">${result.folderPath}</span>
          <a href="${folderUrl}" class="open-folder-btn" title="Open Folder">📂 Open Folder</a>
        </div>

        <div class="action-buttons">
          <button class="${cdnClass}" onclick="generateSearchShareLink('${result.key}', this, true)" title="CDN Link - Fast cached delivery">
            🚀 CDN Link${cdnBadge}
          </button>
          <button class="${directClass}" onclick="generateSearchShareLink('${result.key}', this, false)" title="Direct S3 Link">
            🔗 Direct Link${directBadge}
          </button>
          ${isPreviewable(result.name) ? `<a href="/${result.key}?preview=true" class="action-btn preview-btn" target="_blank">👁️ Preview</a>` : ''}
          <a href="/${result.key}?download=true" class="action-btn download-btn">
            📥 Download
          </a>
        </div>
      </div>
    `;
  }).join('') : `
    <div class="empty-state">
      <div class="empty-icon">🔍</div>
      <h3>No files found</h3>
      <p>Try different keywords or check spelling. Search works across all cloud providers.</p>
      <div class="search-tips">
        <h4>💡 Search Tips:</h4>
        <ul>
          <li>Use partial filenames (e.g., "video" finds "my-video.mp4")</li>
          <li>Search is case-insensitive</li>
          <li>Files in subfolders are included automatically</li>
          <li>Minimum 2 characters required</li>
        </ul>
      </div>
      <a href="/" class="back-home-btn">← Back to Home</a>
    </div>
  `;

  const currentTheme = CONFIG.availableThemes[CONFIG.theme];

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Search Results - ${CONFIG.siteName}</title>
  <style>
    :root {
      --bg-gradient: ${currentTheme.background};
      --surface: ${currentTheme.surface};
      --surface-secondary: ${currentTheme.surfaceSecondary};
      --text: ${currentTheme.text};
      --text-secondary: ${currentTheme.textSecondary};
      --accent: ${currentTheme.accent};
      --accent-secondary: ${currentTheme.accentSecondary};
      --border: ${currentTheme.border};
      --success: ${currentTheme.success};
      --error: ${currentTheme.error};
      --warning: ${currentTheme.warning};
      --border-radius: 16px;
      --border-radius-sm: 12px;
      --border-radius-xs: 8px;
      --shadow: 0 4px 20px rgba(0,0,0,0.08);
      --shadow-hover: 0 12px 32px rgba(0,0,0,0.12);
      --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-gradient);
      color: var(--text);
      min-height: 100vh;
      line-height: 1.6;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
    }

    .header {
      text-align: center;
      margin-bottom: 30px;
      padding: 30px 0;
    }

    .header h1 {
      font-size: 2.5rem;
      font-weight: 700;
      margin-bottom: 10px;
      background: linear-gradient(135deg, var(--accent), var(--success));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .header p {
      font-size: 1.1rem;
      color: var(--text-secondary);
    }

    .search-stats {
      display: flex;
      justify-content: center;
      gap: 30px;
      margin-bottom: 30px;
      flex-wrap: wrap;
    }

    .stat-item {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--surface-secondary);
      padding: 12px 20px;
      border-radius: var(--border-radius-sm);
      box-shadow: var(--shadow);
    }

    .stat-icon {
      font-size: 1.2rem;
    }

    .error-banner {
      background: var(--error);
      color: white;
      padding: 20px;
      border-radius: var(--border-radius-sm);
      margin-bottom: 30px;
      display: flex;
      align-items: flex-start;
      gap: 15px;
      box-shadow: var(--shadow);
    }

    .error-icon {
      font-size: 2rem;
      flex-shrink: 0;
    }

    .error-list {
      list-style: none;
      margin-top: 10px;
    }

    .error-list li {
      margin-bottom: 5px;
    }

    .results-grid {
      display: grid;
      gap: 20px;
    }

    .search-result-card {
      background: var(--surface);
      border-radius: var(--border-radius);
      padding: 24px;
      box-shadow: var(--shadow);
      transition: var(--transition);
      border: 1px solid var(--border);
    }

    .search-result-card:hover {
      box-shadow: var(--shadow-hover);
      transform: translateY(-2px);
    }

    .result-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 16px;
      flex-wrap: wrap;
      gap: 15px;
    }

    .file-info {
      flex: 1;
      min-width: 200px;
    }

    .file-name {
      font-size: 1.3rem;
      font-weight: 600;
      margin-bottom: 8px;
      word-break: break-word;
    }

    .file-meta {
      display: flex;
      gap: 20px;
      flex-wrap: wrap;
    }

    .file-meta span {
      display: flex;
      align-items: center;
      gap: 5px;
      font-size: 0.9rem;
      color: var(--text-secondary);
    }

    .provider-badge {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--accent-secondary);
      padding: 8px 16px;
      border-radius: var(--border-radius-xs);
      font-weight: 500;
      color: var(--accent);
      flex-shrink: 0;
    }

    .folder-path {
      background: var(--surface-secondary);
      padding: 12px 16px;
      border-radius: var(--border-radius-xs);
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .folder-icon {
      font-size: 1.1rem;
    }

    .folder-text {
      flex: 1;
      font-family: monospace;
      font-size: 0.9rem;
      color: var(--text-secondary);
      word-break: break-all;
    }

    .open-folder-btn {
      color: var(--accent);
      text-decoration: none;
      font-weight: 500;
      padding: 6px 12px;
      border-radius: var(--border-radius-xs);
      transition: var(--transition);
      font-size: 0.9rem;
    }

    .open-folder-btn:hover {
      background: var(--accent-secondary);
    }

    .action-buttons {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }

    .action-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 10px 16px;
      border-radius: var(--border-radius-xs);
      text-decoration: none;
      font-weight: 500;
      font-size: 0.9rem;
      transition: var(--transition);
      flex-shrink: 0;
      border: none;
      cursor: pointer;
    }

    .action-btn.btn-recommended {
      position: relative;
      box-shadow: 0 0 0 2px var(--accent), 0 4px 12px rgba(77, 159, 255, 0.3) !important;
      animation: pulse-glow 2s ease-in-out infinite;
    }

    .action-btn.btn-dimmed {
      opacity: 0.5;
    }

    .action-btn.btn-dimmed:hover {
      opacity: 0.7;
    }

    .cdn-btn {
      background: var(--success);
      color: white;
    }

    .cdn-btn:hover {
      background: #218838;
      transform: translateY(-1px);
    }

    .direct-btn {
      background: var(--accent);
      color: white;
    }

    .direct-btn:hover {
      background: #0056b3;
      transform: translateY(-1px);
    }

    .preview-btn {
      background: var(--warning);
      color: white;
    }

    .preview-btn:hover {
      background: #d39e00;
      transform: translateY(-1px);
    }

    .download-btn {
      background: var(--surface-secondary);
      color: var(--text);
      border: 1px solid var(--border);
    }

    .download-btn:hover {
      background: var(--surface);
      transform: translateY(-1px);
    }

    .empty-state {
      text-align: center;
      padding: 80px 20px;
      background: var(--surface);
      border-radius: var(--border-radius);
      box-shadow: var(--shadow);
    }

    .empty-icon {
      font-size: 4rem;
      margin-bottom: 20px;
      opacity: 0.7;
    }

    .empty-state h3 {
      font-size: 1.8rem;
      margin-bottom: 15px;
      color: var(--text-secondary);
    }

    .empty-state p {
      font-size: 1.1rem;
      margin-bottom: 30px;
      color: var(--text-secondary);
    }

    .search-tips {
      background: var(--surface-secondary);
      padding: 20px;
      border-radius: var(--border-radius-sm);
      margin-bottom: 30px;
      text-align: left;
      max-width: 500px;
      margin-left: auto;
      margin-right: auto;
    }

    .search-tips h4 {
      margin-bottom: 15px;
      color: var(--accent);
    }

    .search-tips ul {
      padding-left: 20px;
    }

    .search-tips li {
      margin-bottom: 8px;
    }

    .back-home-btn {
      display: inline-block;
      background: var(--accent);
      color: white;
      padding: 12px 24px;
      border-radius: var(--border-radius-sm);
      text-decoration: none;
      font-weight: 500;
      transition: var(--transition);
    }

    .back-home-btn:hover {
      background: #0056b3;
      transform: translateY(-1px);
    }

    @media (max-width: 768px) {
      .container {
        padding: 15px;
      }

      .header h1 {
        font-size: 2rem;
      }

      .search-stats {
        gap: 15px;
      }

      .stat-item {
        padding: 10px 15px;
        font-size: 0.9rem;
      }

      .result-header {
        flex-direction: column;
        align-items: flex-start;
      }

      .provider-badge {
        align-self: flex-end;
      }

      .action-buttons {
        flex-direction: column;
      }

      .action-btn {
        justify-content: center;
        width: 100%;
      }

      .folder-path {
        flex-direction: column;
        align-items: flex-start;
        gap: 8px;
      }

      .open-folder-btn {
        align-self: flex-end;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <h1>🔍 Search Results</h1>
      <p>Global search across all your cloud storage providers</p>
    </header>

    ${stats}
    ${errorBanner}

    <div class="results-grid">
      ${resultCards}
    </div>
  </div>
  <script>
    // Toast notification system
    function showToast(message, type = 'info') {
      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.textContent = message;
      toast.style.cssText = 'position:fixed;bottom:20px;right:20px;padding:15px 20px;background:#252525;color:#e0e0e0;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.3);z-index:10000;animation:slideIn 0.3s ease';
      document.body.appendChild(toast);
      setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
      }, 3000);
    }

    // Generate share link for search results
    async function generateSearchShareLink(fileKey, element, useCDN) {
      const originalHTML = element.innerHTML;
      element.innerHTML = '<div style="width:16px;height:16px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:spin 0.6s linear infinite"></div>';
      element.disabled = true;

      try {
        const cdnParam = useCDN ? '&cdn=true' : '';
        const response = await fetch('/' + fileKey + '?share=true' + cdnParam);
        const data = await response.json();

        if (response.ok && data.success) {
          const toastMsg = useCDN 
            ? '🚀 CDN link copied! (Fast for repeated viewing)' 
            : '🔗 Direct S3 link copied! (Best compatibility)';

          navigator.clipboard.writeText(data.url).then(() => {
            element.innerHTML = '✅';
            showToast(toastMsg, 'success');
            setTimeout(() => {
              element.innerHTML = originalHTML;
              element.disabled = false;
            }, 2000);
          }).catch(err => {
            console.error('Failed to copy text: ', err);
            showToast('Failed to copy link.', 'error');
            element.innerHTML = originalHTML;
            element.disabled = false;
          });
        } else {
          throw new Error(data.error || 'Failed to generate link');
        }
      } catch (err) {
        console.error('Failed to generate share link:', err);
        showToast('Failed to generate share link: ' + err.message, 'error');
        element.innerHTML = originalHTML;
        element.disabled = false;
      }
    }
  </script>
  <style>
    @keyframes slideIn {
      from { transform: translateX(400px); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
      from { transform: translateX(0); opacity: 1; }
      to { transform: translateX(400px); opacity: 0; }
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  </style>
</body>
</html>`;
}
