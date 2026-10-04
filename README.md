# Cloudflare Worker Identity & Dynamic Asset Gateway

This repository contains an enterprise-grade **Cloudflare Worker** integrated with **Cloudflare Zero Trust (Access)** and **Cloudflare R2 Object Storage**. 

It demonstrates edge-side identity parsing, dynamic HTML rendering, and secure, egress-free asset distribution served directly from Cloudflare's global edge network.

---


## Key Features

- **Zero-Trust Identity Extraction:** Parses identity headers injected by Cloudflare Access (`CF-Access-Authenticated-User-Email`) and request metadata (`request.cf.country`).
- **Dynamic Edge HTML Rendering:** Returns authenticated user session metadata (`${EMAIL} authenticated at ${TIMESTAMP} from ${COUNTRY}`) formatted as HTML.
- **Private R2 Object Streaming:** Fetches country flag SVG assets from a private R2 bucket and serves them with appropriate `image/svg+xml` headers.
- **Infrastructure as Code (IaC):** Full deployment and binding configurations defined using `wrangler.jsonc`.

---

## Prerequisites

Before running or deploying this project, ensure you have:

1. [Node.js](https://nodejs.org/) (v18 or higher) installed.
2. A **Cloudflare Account** with a domain added to Cloudflare DNS.
3. [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/get-started/) installed globally or locally via `npm`.
4. A **Cloudflare R2 Bucket** created in your dashboard or via CLI.

---

## Repository Structure

```text
.
├── src/
│   └── index.mjs         # Worker source code (routing & R2 binding logic)
├── wrangler.jsonc        # Cloudflare Wrangler configuration & bindings
├── package.json          # Project dependencies and scripts
└── README.md             # Repository documentation
```

Getting Started
1. Clone the Repository

git clone [https://github.com/mehmetalatas/cf-app-svc-assignment.git](https://github.com/mehmetalatas/cf-app-svc-assignment.git)
cd cf-app-svc-assignment

3. Install Dependencies

npm install

5. Configure Cloudflare R2 Bucket
Create a private R2 bucket named country-flags and upload your SVG assets (e.g., us.svg, uk.svg, pt.svg):

6. Configure wrangler.jsonc
{
  "name": "cf-worker-assignment",
  "main": "src/index.mjs",
  "compatibility_date": "2026-10-01",
  "r2_buckets": [
    {
      "binding": "FLAGS_BUCKET",
      "bucket_name": "country-flags"
    }
  ],
  "routes": [
    {
      "pattern": "[tunnel.yourwebsite.com/secure](https://tunnel.yourwebsite.com/secure)*",
      "zone_name": "yourwebsite.com"
    }
  ]
}

Local Development & Testing
Run the Worker locally using Wrangler:

npx wrangler dev

# Log in to Cloudflare

npx wrangler login

# Deploy Worker to Cloudflare Edge

npx wrangler deploy

Verification
Once deployed and configured behind Cloudflare Access:

Identity Response (/secure):

Navigate to https://tunnel.yourwebsite.com/secure in your browser. After authenticating via SSO, you will receive an HTML response:

HTML
user@example.com authenticated at 2026-10-04T12:00:00.000Z from <a href="/secure/pt">PT</a>
Flag Asset Response (/secure/pt):

Clicking the country link navigates to https://tunnel.yourwebsite.com/secure/pt, returning the country flag SVG with Content-Type: image/svg+xml.
