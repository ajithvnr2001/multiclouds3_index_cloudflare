# Multi-Cloud S3 Index for Cloudflare Workers

A unified, serverless web interface to browse, preview, share, and delete files stored in **ImpossibleCloud**, **Wasabi**, **Cloudflare R2**, and **Oracle Cloud (OCI)** S3-compatible storage. Powered by Cloudflare Workers, this tool provides a single pane of glass for all your buckets.

-----

## ✨ Features

  - 📁 **Unified Browser:** Browse folders and files from ImpossibleCloud, Wasabi, Cloudflare R2, and Oracle Cloud under a single interface.
  - 🚀 **Automatic Routing:** Routes to the correct provider based on URL path prefixes (e.g., `/r2/`, `/oci/`, `/wasabi/`).
  - ⬇️ **Download & Stream:** Securely download or stream files, with support for browser-based video/audio playback.
  - 👁️ **Media Previews:** In-browser previews for images, videos (including enhanced MKV support), audio, and PDFs.
  - 🔗 **Smart Sharing:**
      - Generates 7-day secure, presigned URLs for ImpossibleCloud, Wasabi, and R2.
      - Generates **permanent public URLs** for Oracle Cloud (requires a public OCI bucket).
  - 🗑️ **Delete Files:** Remove files directly from your buckets via the web interface.
  - 🔒 **Password Protection:** Optional global password protection using HTTP Basic Auth.
  - 🎨 **Responsive Theme:** Dark theme, responsive for both desktop and mobile.
  - 🌍 **Edge Deployment:** Deploy globally on the Cloudflare edge network for ultra-low latency.
  - 🔐 **Secure Signing:** Uses AWS Signature V4 for all S3 API requests.

-----

## 📋 Prerequisites

  - A Cloudflare account with Workers enabled ([Dashboard](https://dash.cloudflare.com))
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

  - Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com) → Workers & Pages → Create Worker.
  - Copy and paste the complete `index.js` worker code.
  - Save and deploy.

### 3\. Configure Environment Variables

Go to the Worker's settings → Variables and add the following. You only need to add variables for the providers you are using.

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
| `R2_ACCOUNT_ID` | `f9e8d7c6b5a4...` | **Required.** Your Cloudflare Account ID |
| `OCI_ACCESS_KEY_ID` | `OCI...` | Oracle Cloud Access Key |
| `OCI_SECRET_ACCESS_KEY` | `zYxWvU...` | Oracle Cloud Secret Key |
| `OCI_BUCKET_NAME` | `my-oci-bucket` | Oracle Cloud Bucket Name |
| `OCI_NAMESPACE` | `axbycz...` | **Required.** Your OCI Tenancy Namespace |
| `OCI_REGION` | `ap-hyderabad-1` | Oracle Cloud Region |

**Important:** Encrypt all **Secret Access Keys** for best security.

### 4\. Access Your Interface

  - Visit your Worker URL (e.g., `https://multi-cloud.my-worker.workers.dev/`).
  - The interface will show buttons to navigate to each provider's root:
      - `/impossible/` → Browses ImpossibleCloud
      - `/wasabi/` → Browses Wasabi
      - `/r2/` → Browses Cloudflare R2
      - `/oci/` → Browses Oracle Cloud
  - The `default` provider (set in `CONFIG`) will be shown at the `/` root.

-----

## ⚙️ Configuration Options

Edit the `CONFIG` object at the top of the Worker code to customize your deployment.

```js
const CONFIG = {
  siteName: "Multi-Cloud S3 Index",
  siteIcon: "🌤️",
  theme: "dark", // "dark" or "light"
  passwordProtected: false,
  password: "", // If protected, set a strong password here
  experimentalMkvSupport: true,
  routingStrategy: "path-based",
  pathRouting: {
    "impossible/": "impossiblecloud",
    "wasabi/": "wasabi",
    "r2/": "cloudflarer2",
    "oci/": "oraclecloud",
    default: "impossiblecloud" // Provider to show at the root path "/"
  },
  providerPriority: ["impossiblecloud", "wasabi", "cloudflarer2", "oraclecloud"]
};
```

-----

## Troubleshooting

  - **Authentication Errors:** Double-check your keys, regions, and bucket names. For R2, ensure `R2_ACCOUNT_ID` is set. For OCI, ensure `OCI_NAMESPACE` is set.
  - **OCI Public Links Not Working:** The "Share (Public)" button for OCI generates a direct public URL. This **requires** your OCI bucket to be public. If your bucket is private, this link will fail with an auth error.
  - **Delete Failed:** The S3 keys you use must have `s3:DeleteObject` permissions.
  - **File Not Found:** Ensure your URL path includes the correct provider prefix (e.g., `/r2/my-folder/file.txt`).

-----

## License

MIT License

-----

## Credits

  - [Cloudflare Workers](https://developers.cloudflare.com/workers)
  - [ImpossibleCloud](https://impossiblecloud.com)
  - [Wasabi Hot Cloud Storage](https://wasabi.com)
  - [Cloudflare R2](https://www.cloudflare.com/products/r2/)
  - [Oracle Cloud Infrastructure](https://www.oracle.com/cloud/)
