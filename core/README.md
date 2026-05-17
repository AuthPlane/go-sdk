# Authplane Go SDK — core

[![Go Reference](https://pkg.go.dev/badge/github.com/authplane/go-sdk/core.svg)](https://pkg.go.dev/github.com/authplane/go-sdk/core)

Framework-agnostic OAuth 2.1 JWT validation, JWKS caching, DPoP, RFC 7662 introspection, RFC 8693 token exchange, and RFC 9728 Protected Resource Metadata.

## Install

```bash
go get github.com/authplane/go-sdk/core
```

## Quickstart

```go
package main

import (
    "context"
    "log"

    "github.com/authplane/go-sdk/core/authplane"
    "github.com/authplane/go-sdk/core/resource"
)

func main() {
    ctx := context.Background()

    client, err := authplane.NewClient(ctx, "https://auth.example.com",
        authplane.WithClientCredentials("my-client", "s3cret"),
    )
    if err != nil {
        log.Fatalf("create client: %v", err)
    }
    defer client.Close() // stops JWKS refresh goroutines, closes idle HTTP connections

    res, err := client.Resource("https://api.example.com",
        resource.WithScopes("read", "write"),
    )
    if err != nil {
        log.Fatalf("create resource: %v", err)
    }

    claims, err := res.VerifyToken(ctx, token)
    if err != nil {
        log.Fatalf("verify: %v", err)
    }
    log.Printf("sub=%s client_id=%s scopes=%v", claims.Sub(), claims.ClientID(), claims.Scopes())
}
```

See the **[User Guide](docs/user-guide.md)** for configuration, token operations, DPoP, revocation, PRM, error handling, and advanced usage.
