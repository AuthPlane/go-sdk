# Authplane Go SDK — mcp

[![Go Reference](https://pkg.go.dev/badge/github.com/authplane/go-sdk/mcp.svg)](https://pkg.go.dev/github.com/authplane/go-sdk/mcp)

Adapter between the [Authplane core SDK](../core/README.md) and the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk). Validates OAuth 2.1 JWT access tokens, serves RFC 9728 Protected Resource Metadata, and bridges RFC 8693 token exchange to the MCP URL elicitation flow.

## Install

```bash
go get github.com/authplane/go-sdk/mcp
```

## Quickstart

```go
package main

import (
    "context"
    "net/http"

    "github.com/authplane/go-sdk/mcp/pkg/authplanemcp"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
    ctx := context.Background()

    adapter, err := authplanemcp.NewAdapter(ctx, authplanemcp.Options{
        Issuer:   "https://auth.example.com",
        Resource: "https://mcp.example.com/mcp",
        Scopes:   []string{"tools/query", "tools/write"},
    })
    if err != nil {
        panic(err)
    }
    defer adapter.Close() // stops background refresh goroutines, closes the client

    server := mcp.NewServer(&mcp.Implementation{Name: "My Server", Version: "1.0.0"}, nil)

    handler := mcp.NewStreamableHTTPHandler(
        func(_ *http.Request) *mcp.Server { return server }, nil,
    )

    http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
    http.Handle("/mcp", adapter.AuthMiddleware(handler))

    http.ListenAndServe(":8080", nil)
}
```

See the **[User Guide](docs/user-guide.md)** for the full API, per-tool scope enforcement, revocation checking, token exchange with URL elicitation, dev mode, and lifecycle details.
