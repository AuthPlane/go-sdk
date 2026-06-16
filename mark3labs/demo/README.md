# Calculator Service Example — mark3labs/mcp-go

A minimal MCP server built with [`github.com/mark3labs/mcp-go`](https://github.com/mark3labs/mcp-go) and the Authplane adapter, demonstrating JWT authentication with per-tool scope enforcement.

The server exposes two tools:

| Tool | Required scope |
|------|----------------|
| `add` | `tools/add` |
| `multiply` | `tools/multiply` |

A token with only `tools/add` can call `add` but not `multiply`.

## Prerequisites

- Go 1.25.5+
- The **Authplane authserver** running locally — from a checkout of the `authserver` repo, run:

  ```bash
  bash demo/mcp-demo-server-start.sh
  ```

  This starts the auth server on `http://localhost:9000`, registers the calculator client and scopes, and creates a demo user.

## Run

```bash
cd go-sdk/mark3labs
./demo/run.sh
```

All demo credentials are pre-configured — no additional setup needed. The server starts on port `8080`.

## How it works

```
MCP Client ──Bearer JWT──► demo/main.go (port 8080)
                                │
                                ├─ authplanemark3labs.NewAdapter()
                                │    • Discovers AS metadata + JWKS (RFC 8414)
                                │    • Validates JWT signature, aud, exp
                                │    • Introspects token for revocation (RFC 7662)
                                │    • Injects VerifiedClaims into HTTP request context
                                │
                                ├─ server.WithHTTPContextFunc(adapter.HTTPContextFunc())
                                │    • Forwards claims into the per-tool-call MCP context
                                │
                                └─ claims.RequireScope("tools/add")
                                     • Tool handler reads claims via ClaimsFromContext()
                                     • Returns isError=true CallToolResult on missing scope
```

## Key patterns shown

**`ClientOptions` with `authplane.WithClientCredentials`** — providing credentials automatically wires RFC 7662 token introspection (revocation checking). No separate `WithIntrospection` option needed.

**`adapter.AuthMiddleware(streamable)`** — wraps the `*server.StreamableHTTPServer` (which is an `http.Handler`) with bearer-token verification.

**`server.WithHTTPContextFunc(adapter.HTTPContextFunc())`** — the bridge. mark3labs/mcp-go invokes this once per HTTP request to derive the context that tool handlers see. Without it, tool handlers receive a fresh context with no claims.

**`authplanemark3labs.ClaimsFromContext(ctx)`** — retrieves the `VerifiedClaims` from inside a tool handler.

**`claims.RequireScope(scope)` → `mcp.NewToolResultError(...)`** — mark3labs/mcp-go coerces any error returned from a tool handler to JSON-RPC `-32603` (INTERNAL_ERROR), so scope failures are surfaced as `IsError: true` tool results instead. The MCP client sees a structured failure with the message intact.
