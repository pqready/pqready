# pqready MCP — Cloudflare Worker

Thin auth + streaming proxy in front of a backend that runs
`pqready-mcp` over HTTP/SSE. The Python runtime cannot execute directly inside
a Worker, so this layer handles bearer-token auth and forwards everything else
to your backend (Cloud Run, Fly, VPS, etc.).

## Endpoints

| Route        | Auth     | Description                                   |
| ------------ | -------- | --------------------------------------------- |
| `GET /health`| none     | Liveness probe — returns `{status, version}`. |
| `POST /mcp`  | Bearer   | Forwarded verbatim to `PQREADY_BACKEND_URL`.  |

## Configuration

`wrangler.toml`:

```toml
[vars]
PQREADY_BACKEND_URL = "https://your-backend.example/mcp"
```

Set the bearer token as a secret:

```bash
wrangler secret put PQREADY_API_TOKEN
```

## Develop & deploy

```bash
npm install
npm run dev      # local dev server
npm run deploy   # publish to Cloudflare
```

## Client usage

```bash
curl https://mcp.pqready.com/mcp \
  -H "Authorization: Bearer $PQREADY_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```
