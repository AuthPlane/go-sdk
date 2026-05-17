# Calculator Service Example

A minimal MCP server demonstrating Authplane JWT authentication with per-tool scope enforcement.

The server exposes two tools:

| Tool | Required scope |
|------|----------------|
| `add` | `tools/add` |
| `multiply` | `tools/multiply` |

Tokens must carry the scope for the specific tool being called. A token with only `tools/add` can call `add` but not `multiply`.

## Prerequisites

- Go 1.25+
- The **Authplane authserver** running locally — from a checkout of the `authserver` repo, run:

  ```bash
  bash demo/mcp-demo-server-start.sh
  ```

  This starts the auth server on `http://localhost:9000`, registers the calculator client and scopes, and creates a demo user.

## Run

```bash
cd mcp
./demo/run.sh
```

All demo credentials are pre-configured — no additional setup needed. The server starts on port `8080`.

## Try it with Claude

With the demo server running, add it to Claude Code:

```bash
claude mcp add --transport http authplane-demo http://localhost:8080/mcp
```

Claude Code discovers the server's Protected Resource Metadata, handles the OAuth authorization flow, and makes the `add` and `multiply` tools available in the conversation. Ask Claude to call them and it will use the authorized token automatically.

## How it works

```
MCP Client ──Bearer JWT──► demo/main.go (port 8080)
                                │
                                ├─ authplanemcp.NewAdapter()
                                │    • Discovers AS metadata + JWKS (RFC 8414)
                                │    • Validates JWT signature, aud, exp
                                │    • Introspects token for revocation (RFC 7662)
                                │    • Injects VerifiedClaims into request context
                                │
                                └─ claims.RequireScope("tools/add")
                                     • Reads claims from context via ClaimsFromContext()
                                     • Returns error if scope missing
                                       → MCP returns isError=true to client
```

## Key patterns shown

**`ClientOptions` with `authplane.WithClientCredentials`** — providing credentials automatically wires RFC 7662 token introspection (revocation checking). No separate `WithIntrospection` option needed.

**`authplanemcp.NewAdapter()`** — wires up the client and auth middleware. The `Scopes` list advertises supported scopes in the Protected Resource Metadata; it does **not** require all scopes to be present in every token.

**`authplanemcp.ClaimsFromContext(ctx)`** — retrieves the `VerifiedClaims` injected by `AuthMiddleware` into the request context. Call this at the top of any tool handler to access the token's scopes.

**`claims.RequireScope(scope)`** — enforces per-tool scope. Returns an error if the token is missing the scope, which the MCP SDK surfaces as `isError: true` to the client.
