# Calculator Service Example (REST API)

A minimal REST API server demonstrating Authplane JWT authentication with per-route scope enforcement. This is a plain HTTP service — **not** an MCP server. It shows how to protect standard REST endpoints with OAuth 2.1 tokens using the `authplane-http` adapter.

The server exposes two routes:

| Route | Required scope |
|-------|----------------|
| `POST /mcp/add` | `tools/add` |
| `POST /mcp/multiply` | `tools/multiply` |

Tokens must carry the scope for the specific route being called. A token with only `tools/add` can call `/mcp/add` but not `/mcp/multiply`.

## Prerequisites

- Go 1.24+
- The **Authplane authserver** running locally — from a checkout of the `authserver` repo, run:

  ```bash
  bash demo/mcp-demo-server-start.sh
  ```

  This starts the auth server on `http://localhost:9000`, registers the calculator client and scopes, and creates a demo user.

## Run

```bash
cd http
./demo/run.sh
```

All demo credentials are pre-configured — no additional setup needed. The server starts on port `8080`.

## Try it

Once both the authorization server and calculator service are running:

**1. Discover the resource's protected metadata (no token required):**

```bash
curl http://localhost:8080/.well-known/oauth-protected-resource/mcp
```

This returns the RFC 9728 Protected Resource Metadata — scopes, authorization server, and token formats.

**2. Obtain a token from the authorization server:**

```bash
CLIENT_ID=$(cat /tmp/authserver-demo.client-id)
CLIENT_SECRET=$(cat /tmp/authserver-demo.key)

TOKEN=$(curl -s -X POST http://localhost:9000/oauth/token \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d "grant_type=client_credentials&scope=tools/add tools/multiply" \
  | jq -r .access_token)
```

**3. Call a protected endpoint:**

```bash
# Add — requires tools/add scope
curl -s http://localhost:8080/mcp/add \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"a": 3, "b": 4}'
# → {"result":7}

# Multiply — requires tools/multiply scope
curl -s http://localhost:8080/mcp/multiply \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"a": 3, "b": 4}'
# → {"result":12}
```

**4. See what happens without a token:**

```bash
curl -i http://localhost:8080/mcp/add \
  -H "Content-Type: application/json" \
  -d '{"a": 3, "b": 4}'
# → 401 Unauthorized with WWW-Authenticate header
```

## How it works

```
HTTP Client ──Bearer JWT──► demo/main.go (port 8080)
                                │
                                ├─ authplanehttp.New(res)
                                │    • Discovers AS metadata + JWKS (RFC 8414)
                                │    • Validates JWT signature, aud, exp
                                │    • Introspects token for revocation (RFC 7662)
                                │    • Injects VerifiedClaims into request context
                                │
                                └─ adapter.RequireScopes("tools/add")
                                     • Reads claims from context via ClaimsFromContext()
                                     • Returns 403 if scope missing
                                       → RFC 6750 WWW-Authenticate header with scope= param
```

## Key patterns shown

**`ClientOptions` with `authplane.WithClientCredentials`** — providing credentials automatically wires RFC 7662 token introspection (revocation checking). No separate `WithIntrospection` option needed.

**`authplanehttp.New(res)`** — wraps a `resource.Resource` without owning its lifecycle. The caller manages `client.Close()`. The `Scopes` list advertises supported scopes in the Protected Resource Metadata; it does **not** require all scopes to be present in every token.

**`adapter.Middleware()`** — standard `net/http` middleware applied to the entire mux. Validates Bearer and DPoP tokens, writes RFC 6750 error responses on failure, and injects `VerifiedClaims` into the request context on success. The PRM discovery endpoint is automatically excluded from authentication.

**`adapter.RequireScopes("tools/add")(handler)`** — per-route scope enforcement. Wrap individual route handlers to gate access by scope. Returns 403 with a RFC 6750 `WWW-Authenticate` header (including `scope=` parameter) if the token is missing the required scope.

**`authplanehttp.ClaimsFromContext(r.Context())`** — retrieves the `VerifiedClaims` injected by `Middleware` into the request context. Call this inside any handler to access the token's scopes or other claims.
