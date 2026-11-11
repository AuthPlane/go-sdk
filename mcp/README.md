# Authplane Go SDK — mcp

[![Go Reference](https://pkg.go.dev/badge/github.com/authplane/go-sdk/mcp.svg)](https://pkg.go.dev/github.com/authplane/go-sdk/mcp)

Adapter between the [Authplane core SDK](../core/README.md) and the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk). Validates OAuth 2.1 JWT access tokens, serves RFC 9728 Protected Resource Metadata, and bridges RFC 8693 token exchange to the MCP URL elicitation flow.

## Install

```bash
go get github.com/authplane/go-sdk/mcp
```

## Quickstart

A server with one tool, RFC 9728 metadata served, and every request authenticated:

```go
package main

import (
	"context"
	"net/http"

	"github.com/authplane/go-sdk/mcp/pkg/authplanemcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	adapter, err := authplanemcp.NewAdapter(context.Background(), authplanemcp.Options{
		Issuer:   "https://auth.example.com",
		Resource: "https://mcp.example.com/mcp",
		Scopes:   []string{"tools/ping"},
	})
	if err != nil {
		panic(err)
	}
	defer adapter.Close() // stops background refresh goroutines, closes the client
	server := mcp.NewServer(&mcp.Implementation{Name: "Ping", Version: "0.1.0"}, nil)
	server.AddReceivingMiddleware(adapter.ReceivingMiddleware())
	mcp.AddTool(server, &mcp.Tool{Name: "ping"}, func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "pong"}}}, nil, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true})
	http.Handle(adapter.WellKnownPRMPath(), adapter.PRMHandler())
	http.Handle("/mcp", adapter.AuthMiddleware(handler))
	http.ListenAndServe(":8080", nil)
}
```

```bash
go run .
```

Unauthenticated calls now get a 401 pointing at the metadata document; authenticated ones reach the tool.

## Next steps

- [Scope-gated tools](docs/user-guide.md#43-enforce-scope-inside-tool-handlers) — `Options.Scopes` is only advertised in the metadata document; the middleware accepts any valid token for the resource. Gate individual tools with `ClaimsFromContext(ctx).RequireScope(...)`.
- [Token exchange and consent](docs/user-guide.md#7-token-exchange-and-url-elicitation) — RFC 8693 exchange bridged to MCP URL elicitation.
- [Verified JWT claims](docs/user-guide.md#6-main-api-reference) — read `ClaimsFromContext` / `TokenFromContext` inside a tool.
- [Serving Protected Resource Metadata](docs/user-guide.md#42-mount-the-handlers) — the RFC 9728 document and its well-known path.

See the **[User Guide](docs/user-guide.md)** for the full API, revocation checking, DPoP, dev mode, and lifecycle details.

## Protocol and sessions

This adapter uses MCP go-sdk v1.8. A handler with `Stateless: true` speaks protocol 2026-07-28; a stateful one stays on 2025-11-25 and earlier, with legacy sessions. `ReceivingMiddleware` gives each call its own request's claims, and `RequireToolScopes` answers a missing tool scope with a 403 step-up challenge. DPoP-bound tokens are not supported here, because the SDK's middleware reads bearer tokens only; use the `http` or `mark3labs` adapter for those. See the [user guide](docs/user-guide.md).

## Other authorization servers

This adapter takes the server-neutral options of `core` through `resource.WithVerifierOptions`: `WithAcceptedTokenTypes`, `WithRequiredClaims`, `WithScopeClaims`, `WithClientClaims`, `WithAccessTokenMarkers` and `WithExpectedAudience`. See [Using another authorization server](../core/docs/user-guide.md#using-another-authorization-server).
