# Multi-Cloud S3 Index (ImpossibleCloud + Wasabi) for Cloudflare Workers

A unified, serverless web interface to browse, preview, and download files stored in both ImpossibleCloud and Wasabi S3-compatible storage systems. Powered by Cloudflare Workers, supporting advanced video formats, automatic routing, and seamless cloud integration.

***

## ✨ Features

- 📁 Browse folders and files from both ImpossibleCloud and Wasabi under a single interface
- ⬇️ Download files with secure streaming and authentication
- 👁️ Preview a variety of media formats including enhanced MKV playback with browser codec awareness
- 🚀 Automatic provider routing based on URL path prefixes (e.g., `/impossible/` or `/wasabi/`)
- 🔒 Optional password protection using HTTP Basic Auth
- 🎨 Dark and light theme support with responsive design for desktop and mobile
- 🌍 Deploy globally on Cloudflare edge network for ultra-low latency
- 🔐 Uses AWS Signature V4 for secure API request signing
- ⚡ Displays provider information next to files and folders
- 🛡️ Robust error handling and fallback mechanisms
- 🖼️ Built-in favicon support to avoid missing resources errors

***

## 📋 Prerequisites

- An ImpossibleCloud account and storage bucket ([Sign up here](https://console.impossiblecloud.com))
- A Wasabi account and storage bucket ([Sign up here](https://wasabi.com))
- A Cloudflare account with Workers enabled ([Dashboard](https://dash.cloudflare.com))

***

## 🚀 Setup Instructions

### 1. Obtain API Keys and Buckets

#### ImpossibleCloud

- Create a bucket in your preferred region.
- Generate access keys for S3 API access.
- Note your **Access Key ID**, **Secret Access Key**, **Bucket Name**, and **Region**.

#### Wasabi

- Create a bucket in your preferred region.
- Create programmatic access keys.
- Note your **Access Key ID**, **Secret Access Key**, **Bucket Name**, and **Region**.

### 2. Deploy the Worker

- Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com) → Workers & Pages → Create Worker.
- Copy and paste the complete Worker code from this repository.
- Save and deploy.

### 3. Configure Environment Variables

Go to the Worker settings → Variables and add the following variables:

| Variable Name                  | Example Value            | Description                 |
|-------------------------------|--------------------------|-----------------------------|
| `IMPOSSIBLE_ACCESS_KEY_ID`     | `E66C5D15FDEAA3EE...`    | ImpossibleCloud Access Key  |
| `IMPOSSIBLE_SECRET_ACCESS_KEY` | `ad8fb4f17ce235c69...`   | ImpossibleCloud Secret Key  |
| `IMPOSSIBLE_BUCKET_NAME`       | `my-impossible-bucket`   | ImpossibleCloud Bucket Name |
| `IMPOSSIBLE_REGION`            | `eu-central-2`           | ImpossibleCloud Region      |
| `WASABI_ACCESS_KEY_ID`         | `B75P0FDJF41RI...`       | Wasabi Access Key           |
| `WASABI_SECRET_ACCESS_KEY`     | `3z7ZCpDwQ0nMdbB...`     | Wasabi Secret Key           |
| `WASABI_BUCKET_NAME`           | `my-wasabi-bucket`       | Wasabi Bucket Name          |
| `WASABI_REGION`                | `ap-northeast-1`         | Wasabi Region               |

**Important:** Encrypt secret keys where possible using Cloudflare's secret storage.

### 4. Access Your Interface

- Visit your Worker URL:  
  - Browse ImpossibleCloud files under `/impossible/`  
  - Browse Wasabi files under `/wasabi/`
- File operations auto-detect provider based on URL prefix.
- No manual switching required.

***

## ⚙️ Configuration Options

Edit the `CONFIG` object in the Worker code:

```js
const CONFIG = {
  siteName: "Multi-Cloud S3 Index",
  siteIcon: "🌤️",
  theme: "dark", // "dark" or "light"
  passwordProtected: false,
  password: "", // If enabled, set strong password
  experimentalMkvSupport: true, // Enable enhanced MKV playback
  routingStrategy: "path-based", // Automatic path-based routing enforced
  pathRouting: {
    "impossible/": "impossiblecloud",
    "wasabi/": "wasabi",
    default: "impossiblecloud",
  },
  providerPriority: ["impossiblecloud", "wasabi"],
};
```

***

## Usage Details

- Browse folders by clicking folder names with visible provider icon prefixes.
- Download or preview files directly.
- Breadcrumb navigation shows current folder paths with provider prefixes.
- Video preview uses HTML5 player with codec fallback for MKV files.
- Keyboard control supported: space=play/pause, arrows=seek/volume, F=fullscreen.

***

## Troubleshooting

- **File not found errors:** Make sure URLs include provider prefix `/wasabi/` or `/impossible/`.
- **Authentication errors:** Double-check keys and region environment variables.
- **Slow downloads:** Cloudflare Workers streams can be slower; consider CDN caching strategies.
- **MKV playback issues:** Best supported in Firefox and Chrome, limited in Safari.

***

## Development & Contribution

Fork and contribute via pull requests. Feel free to report issues on GitHub.

***

## License

MIT License - free for personal and commercial use.

***

## Credits

- [Cloudflare Workers](https://developers.cloudflare.com/workers)
- [ImpossibleCloud Storage](https://impossiblecloud.com)
- [Wasabi Hot Cloud Storage](https://wasabi.com)

***

Enjoy seamless multi-cloud file browsing and streaming from a single interface!
