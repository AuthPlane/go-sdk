# Authplane Go SDK — http

[![Go Reference](https://pkg.go.dev/badge/github.com/authplane/go-sdk/http.svg)](https://pkg.go.dev/github.com/authplane/go-sdk/http)

`net/http` middleware for OAuth 2.1 resource servers. Validates Bearer and DPoP sender-constrained tokens, enforces per-route scopes, and serves RFC 9728 Protected Resource Metadata.

## Install

```bash
go get github.com/authplane/go-sdk/http
```

## Quickstart

```go
package main

import (
    "context"
    "net/http"

    "github.com/authplane/go-sdk/core/authplane"
    "github.com/authplane/go-sdk/core/resource"
    "github.com/authplane/go-sdk/http/pkg/authplanehttp"
)

func main() {
    ctx := context.Background()

    client, err := authplane.NewClient(ctx, "https://auth.example.com",
        authplane.WithClientCredentials("my-client", "s3cret"),
    )
    if err != nil {
        panic(err)
    }
    defer client.Close() // stops background refresh goroutines

    res, err := client.Resource("https://api.example.com",
        resource.WithScopes("read", "write"),
    )
    if err != nil {
        panic(err)
    }

    adapter := authplanehttp.New(res)

    mux := http.NewServeMux()
    mux.Handle(adapter.WellKnownPRMPath(), adapter.PRMHandler())
    mux.Handle("/api/admin", adapter.RequireScopes("admin")(http.HandlerFunc(adminHandler)))

    http.ListenAndServe(":8080", adapter.Middleware()(mux))
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(`{"ok":true}`))
}
```

See the **[User Guide](docs/user-guide.md)** for the full API, DPoP, replay stores, per-route scope enforcement, error handling, and lifecycle details.
