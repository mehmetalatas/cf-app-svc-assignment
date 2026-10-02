/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

/**
 * @fileoverview Production Cloudflare Worker serving dynamic HTML and R2 flags.
 * Securely extracts authenticated identity from Cloudflare Access JWTs/headers.
 * Requires valid geolocation metadata; returns 404 if country code is missing or invalid.
 */

// ============================================================================
// CONSTANTS & REGEX PATTERNS
// ============================================================================

/**
 * Validates standard email address syntax (RFC 5322 subset).
 * Prevents header tampering and invalid string injection into HTML/logs.
 */
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

/**
 * Validates ISO 3166-1 alpha-2 country code format (e.g., "US", "PT", "BE").
 * @see https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-ipcountry
 */
const COUNTRY_REGEX = /^[a-zA-Z]{2}$/;

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Safely parses a base64url-encoded JWT payload without external dependencies.
 *
 * @param {string} token - Raw JWT string
 * @returns {object|null} Decoded JSON payload or null if invalid
 */
function parseJwtPayload(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    // Replace base64url characters with base64 standard characters
    let base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4 !== 0) {
      base64 += "=";
    }
    const jsonPayload = atob(base64);
    return JSON.parse(jsonPayload);
  } catch (err) {
    return null;
  }
}

/**
 * Extracts a cookie value by name from a Cookie header string.
 *
 * @param {string|null} cookieHeader - Raw Cookie header value.
 * @param {string} name - Target cookie key.
 * @returns {string|null} Extracted cookie value or null.
 */
function getCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(new RegExp(`(?:^|; )*${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Escapes HTML special characters to prevent Reflected Cross-Site Scripting (XSS).
 *
 * @param {string} str - Raw untrusted input string.
 * @returns {string} HTML-entity-encoded string safe for inline rendering.
 */
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ============================================================================
// WORKER ENTRYPOINT
// ============================================================================

export default {
  /**
   * Main request handler for the Cloudflare Worker runtime.
   *
   * @param {Request} request - Incoming fetch request object.
   * @param {Env} env - Environment bindings (R2, KV, Secrets).
   * @returns {Promise<Response>} HTTP Response object.
   */
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ------------------------------------------------------------------------
    // 1. SECURITY & AUTHENTICATION GUARD (Fail-Fast)
    // ------------------------------------------------------------------------
    let rawEmail = request.headers.get("Cf-Access-Authenticated-User-Email");

    // Fallback: If header is missing, extract from Access JWT assertion or cookie
    if (!rawEmail) {
      const jwtToken =
        request.headers.get("Cf-Access-Jwt-Assertion") ||
        getCookie(request.headers.get("Cookie"), "CF_Authorization");

      if (jwtToken) {
        const payload = parseJwtPayload(jwtToken);
        if (payload?.email) {
          rawEmail = payload.email;
        }
      }
    }

    // Fail-Fast: Reject unauthenticated or malformed identity requests
    if (!rawEmail || !EMAIL_REGEX.test(rawEmail.trim())) {
      return new Response("Access Denied", {
        status: 403,
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }

    // Sanitize validated identity string prior to UI interpolation
    const cleanEmail = escapeHtml(rawEmail.trim());

    // ------------------------------------------------------------------------
    // 2. HTML DOCUMENT ROUTE (/secure and /secure/)
    // ------------------------------------------------------------------------
    if (path === "/secure" || path === "/secure/") {
      // Extract client location metadata from edge runtime or edge header
      const rawCountry =
        request.cf?.country || request.headers.get("CF-IPCountry");

      // Validate presence and ISO 3166-1 alpha-2 format; return 404 if missing or invalid
      if (!rawCountry || !COUNTRY_REGEX.test(rawCountry.trim())) {
        return new Response("Not found", { status: 404 });
      }

      const cleanCountry = rawCountry.trim().toLowerCase();
      const timestamp = new Date().toISOString();

      const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure Area</title>
</head>
<body>
  <p>${cleanEmail} authenticated at ${timestamp} from <a href="/secure/${cleanCountry}">${cleanCountry}</a></p>
</body>
</html>`;

      return new Response(htmlContent, {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store, no-cache, must-revalidate",
          "X-Content-Type-Options": "nosniff",
          "Content-Security-Policy": "default-src 'self'",
        },
      });
    }

    // ------------------------------------------------------------------------
    // 3. ASSET ROUTE (/secure/{country})
    // ------------------------------------------------------------------------
    if (path.startsWith("/secure/")) {
      // Extract target country slug from request path
      const targetCountry = path.replace("/secure/", "").trim().toLowerCase();

      // Guard against invalid country code format or path traversal attempts
      if (!targetCountry || !COUNTRY_REGEX.test(targetCountry)) {
        return new Response("Not found", { status: 404 });
      }

      // Defense-in-depth: Verify storage binding availability
      if (!env.FLAGS_BUCKET) {
        return new Response("Not found", { status: 500 });
      }

      // Key lookup strategy supporting lower and upper case filenames in R2
      const keysToTry = [
        `${targetCountry}.svg`,
        `${targetCountry.toUpperCase()}.svg`,
      ];

      let object = null;
      for (const key of keysToTry) {
        object = await env.FLAGS_BUCKET.get(key);
        if (object) break;
      }

      if (!object) {
        return new Response("Not found", { status: 404 });
      }

      // Preserve R2 object metadata and configure content/security headers
      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set("Content-Type", "image/svg+xml");
      headers.set("X-Content-Type-Options", "nosniff");

      // Enable CDN caching for static SVG assets (24 hours at edge and browser)
      headers.set("Cache-Control", "public, max-age=86400, s-maxage=86400");

      // Set ETag for conditional GET revalidation (HTTP 304)
      if (object.httpEtag) {
        headers.set("etag", object.httpEtag);
      }

      return new Response(object.body, { headers });
    }

    // ------------------------------------------------------------------------
    // 4. FALLBACK ROUTE
    // ------------------------------------------------------------------------
    return new Response("Not found", { status: 404 });
  },
};
