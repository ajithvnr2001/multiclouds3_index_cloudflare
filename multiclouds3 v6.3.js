const CONFIG = {
  siteName: "Multi-Cloud S3 Index",
  siteIcon: "🌤️",
  theme: "dark",
  defaultPath: "",
  passwordProtected: false,
  password: "",
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

      if (CONFIG.passwordProtected && !await checkAuth(request, CONFIG.password)) {
        return new Response(getPasswordPage(), {
          status: 401,
          headers: {
            "Content-Type": "text/html",
            "WWW-Authenticate": 'Basic realm="Multi-Cloud S3 Index"'
          }
        });
      }

      if (url.searchParams.has("search")) {
        return await handleGlobalSearch(url.searchParams.get("search"), env, request);
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

async function checkAuth(request, password) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) return false;
  const [scheme, encoded] = authHeader.split(" ");
  if (scheme !== "Basic") return false;
  const decoded = atob(encoded);
  const [username, pwd] = decoded.split(":");
  return pwd === password;
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
        : '🚀 CDN Link - Large file (${formatSize(item.size)}), may not cache efficiently';
      const directTitle = recommendDirect
        ? '🔗 Direct S3 Link (RECOMMENDED ✨) - Best for large files (${formatSize(item.size)})'
        : '🔗 Direct S3 Link - Best compatibility, direct from S3';

      return `<div class="file-card file-card-item" data-name="${item.name.toLowerCase()}" data-size="${item.size}" data-date="${new Date(item.lastModified).getTime()}" data-type="file" title="${item.name} - ${formatSize(item.size)} - ${formatDate(item.lastModified)}">
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

    ${emptyState || fileGrid}

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
</script>
</body></html>`;
}


function getPasswordPage() {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>Protected - ${CONFIG.siteName}</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#1a1a1a;color:#e0e0e0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.container{text-align:center;background:#252525;padding:40px;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.3)}h1{margin-bottom:20px}p{margin-bottom:30px;color:#999}</style></head><body><div class="container"><h1>🔒 Protected Area</h1><p>Please enter the password to access this multi-cloud storage</p></div></body></html>`;
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
    return new Response(getSearchResultsPage(query, [], [], 'Search query must be at least 2 characters long.'), {
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

  return new Response(getSearchResultsPage(query, allResults, errors), {
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
        results.push({
          ...file,
          fullPath: file.key,
          folderPath: prefix || 'Root'
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
function getSearchResultsPage(query, results, errors) {
  const baseUrl = 'https://' + (typeof window !== 'undefined' ? window.location.host : 'example.com');

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
    const cdnUrl = `${baseUrl}/${result.fullPath}?share=true`;
    const directUrl = `${baseUrl}/${result.fullPath}`;
    const folderUrl = result.folderPath === 'Root' ? '/' : `/${result.folderPath}`;

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
          <a href="${cdnUrl}" class="action-btn cdn-btn" target="_blank">
            🚀 CDN Link ${result.size > 50 * 1024 * 1024 ? '(Large)' : '(Fast)'}
          </a>
          <a href="${directUrl}" class="action-btn direct-btn" target="_blank">
            🔗 Direct Link
          </a>
          ${isPreviewable(result.name) ? `<a href="${directUrl}?preview=true" class="action-btn preview-btn" target="_blank">👁️ Preview</a>` : ''}
          <a href="${directUrl}?download=true" class="action-btn download-btn">
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
</body>
</html>`;
}
