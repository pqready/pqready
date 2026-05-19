/**
 * pqready MCP proxy — Cloudflare Worker.
 *
 * The Python `fastmcp` server cannot run inside a Worker, so this Worker is a
 * thin auth + streaming proxy in front of a backend (Cloud Run, Fly, VPS, …)
 * that runs `pqready-mcp` over HTTP SSE.
 *
 * Routes:
 *   GET  /health  → liveness probe (no auth required)
 *   POST /mcp     → forwards the request body to PQREADY_BACKEND_URL and
 *                   streams the SSE response back to the client.
 *
 * Required bindings:
 *   vars:    PQREADY_BACKEND_URL  — full URL of the upstream MCP endpoint
 *   secrets: PQREADY_API_TOKEN    — shared bearer token clients must present
 */

export interface Env {
  PQREADY_BACKEND_URL: string;
  PQREADY_API_TOKEN: string;
}

const VERSION = "0.2.0";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return jsonResponse({ status: "ok", version: VERSION }, 200);
    }

    if (url.pathname !== "/mcp") {
      return jsonResponse({ error: "not found" }, 404);
    }

    if (!isAuthorized(request, env)) {
      return jsonResponse({ error: "unauthorized" }, 401);
    }

    if (!env.PQREADY_BACKEND_URL) {
      return jsonResponse({ error: "backend not configured" }, 503);
    }

    let upstream: Response;
    try {
      upstream = await fetch(env.PQREADY_BACKEND_URL, {
        method: request.method,
        headers: forwardableHeaders(request.headers),
        body: request.method === "GET" || request.method === "HEAD"
          ? undefined
          : request.body,
      });
    } catch (err) {
      return jsonResponse(
        { error: "backend unreachable", detail: String(err) },
        503,
      );
    }

    const headers = new Headers(upstream.headers);
    // Strip hop-by-hop headers that don't make sense to pass through verbatim.
    headers.delete("transfer-encoding");
    headers.delete("connection");

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers,
    });
  },
};

function isAuthorized(request: Request, env: Env): boolean {
  const expected = env.PQREADY_API_TOKEN;
  if (!expected) return false;
  const header = request.headers.get("authorization") || "";
  const [scheme, token] = header.split(" ");
  if (scheme?.toLowerCase() !== "bearer" || !token) return false;
  return constantTimeEquals(token, expected);
}

function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function forwardableHeaders(input: Headers): Headers {
  const out = new Headers();
  for (const [k, v] of input) {
    const lower = k.toLowerCase();
    if (lower === "host" || lower === "authorization") continue;
    out.set(k, v);
  }
  return out;
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
