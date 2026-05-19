# Authplane Go SDK — mark3labs

[![Go Reference](https://pkg.go.dev/badge/github.com/authplane/go-sdk/mark3labs.svg)](https://pkg.go.dev/github.com/authplane/go-sdk/mark3labs)

Adapter between the [Authplane core SDK](../core/README.md) and [`github.com/mark3labs/mcp-go`](https://github.com/mark3labs/mcp-go). Validates OAuth 2.1 JWT access tokens, serves RFC 9728 Protected Resource Metadata, bridges verified claims into per-tool-call contexts, and maps RFC 8693 token-exchange consent errors to MCP URL elicitation (JSON-RPC -32042).

If you're using the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk) instead, see [`github.com/authplane/go-sdk/mcp`](../mcp/README.md).

## Install

```bash
go get github.com/authplane/go-sdk/mark3labs
```

## Quickstart

```go
package main

import (
    "context"
    "net/http"

    "github.com/authplane/go-sdk/mark3labs/pkg/authplanemark3labs"
    "github.com/mark3labs/mcp-go/server"
)

func main() {
    ctx := context.Background()

    adapter, err := authplanemark3labs.NewAdapter(ctx, authplanemark3labs.Options{
        Issuer:   "https://auth.example.com",
        Resource: "https://mcp.example.com/mcp",
        Scopes:   []string{"tools/query", "tools/write"},
    })
    if err != nil {
        panic(err)
    }
    defer adapter.Close() // stops background refresh goroutines, closes the client

    mcpServer := server.NewMCPServer("My Server", "1.0.0",
        server.WithToolCapabilities(false),
        server.WithRecovery(),
    )

    streamable := server.NewStreamableHTTPServer(mcpServer,
        server.WithHTTPContextFunc(adapter.HTTPContextFunc()),
    )

    http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
    http.Handle("/mcp", adapter.AuthMiddleware(streamable))

    http.ListenAndServe(":8080", nil)
}
```

See the **[User Guide](docs/user-guide.md)** for the full API, per-tool scope enforcement, revocation checking, token exchange, the URL elicitation propagation caveat, dev mode, and lifecycle details.
