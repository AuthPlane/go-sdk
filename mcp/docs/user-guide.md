# Authplane MCP adapter — User Guide

`github.com/authplane/go-sdk/mcp` is a thin adapter between the [Authplane core SDK](../../core/docs/user-guide.md) and the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk). It validates OAuth 2.1 JWT access tokens on MCP server requests, serves RFC 9728 Protected Resource Metadata, and bridges RFC 8693 token exchange to the MCP URL elicitation flow for out-of-band consent.

This guide is the thorough reference. The [README](../README.md) holds the hero snippet.

## 1. Install

```bash
go get github.com/authplane/go-sdk/mcp
```

Requires Go 1.25+. Also pulls in `github.com/authplane/go-sdk/core` and `github.com/modelcontextprotocol/go-sdk`.

## 2. Quickstart

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
    defer adapter.Close()

    server := mcp.NewServer(&mcp.Implementation{Name: "My Server", Version: "1.0.0"}, nil)

    handler := mcp.NewStreamableHTTPHandler(
        func(_ *http.Request) *mcp.Server { return server }, nil,
    )

    http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
    http.Handle("/mcp", adapter.AuthMiddleware(handler))

    http.ListenAndServe(":8080", nil)
}
```

## 3. Core concepts

`NewAdapter` constructs and owns an `*authplane.Client` and a `*resource.Resource`:

1. `authplane.NewClient` performs RFC 8414 AS metadata discovery.
2. `client.Resource(uri, resource.WithScopes(...))` builds the resource (the JWKS cache is warmed and background refresh starts).
3. If `ClientOptions` includes `WithClientCredentials` or `WithClientAuthentication`, RFC 7662 introspection is auto-wired as the revocation checker, and `TokenExchange` becomes operational.

`AuthMiddleware` delegates token extraction to the MCP Go SDK's `auth.RequireBearerToken`, which places `auth.TokenInfo` into the request context (MCP's streamable transport reads it for session binding). The adapter then runs the core verifier, stores the resulting claims in a per-request box, and injects `*verifier.VerifiedClaims` into the context for tool handlers.

Scope enforcement is **per-tool**, not per-request. The middleware itself accepts any valid token; individual tool handlers call `ClaimsFromContext(ctx).RequireScope(...)` to gate access. This matches the MCP protocol: `initialize` and protocol-level messages must succeed with any authenticated client.

## 4. Basic usage

### 4.1 Construct the adapter

```go
adapter, err := authplanemcp.NewAdapter(ctx, authplanemcp.Options{
    Issuer:   "https://auth.example.com",
    Resource: "https://mcp.example.com/mcp",
    Scopes:   []string{"tools/query"},
})
```

All three fields are required. The `Scopes` slice is advertised in the PRM document; it does **not** enforce that every token carries all listed scopes — individual tools decide what they need.

### 4.2 Mount the handlers

```go
http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
http.Handle("/mcp", adapter.AuthMiddleware(mcpHandler))
```

PRM is always served unauthenticated. `AuthMiddleware` is what wraps the MCP HTTP handler.

### 4.3 Enforce scope inside tool handlers

```go
import "github.com/authplane/go-sdk/core/resource/verifier"

type AddArgs struct {
    A float64 `json:"a"`
    B float64 `json:"b"`
}

mcp.AddTool(server, &mcp.Tool{Name: "add", Description: "Add two numbers"},
    func(ctx context.Context, _ *mcp.CallToolRequest, args AddArgs) (*mcp.CallToolResult, any, error) {
        claims := authplanemcp.ClaimsFromContext(ctx)
        if claims == nil {
            return nil, nil, verifier.ErrTokenMissing
        }
        if err := claims.RequireScope("tools/add"); err != nil {
            return nil, nil, err // MCP surfaces this as isError=true
        }
        // ... perform the tool work ...
    },
)
```

`claims` is never nil when the tool is reached through `AuthMiddleware`, but the guard is cheap and makes the handler robust when called from other code paths (tests, direct invocations).

## 5. `Options` reference

| Field | Type | Required | Description |
|---|---|---|---|
| `Issuer` | `string` | yes | Authorization server issuer URL. |
| `Resource` | `string` | yes | Protected resource URL (also used to derive the PRM path). |
| `Scopes` | `[]string` | yes | Scopes advertised in the PRM document. |
| `DevMode` | `bool` | no | Relaxes SSRF to allow HTTP, localhost, private networks. Also enabled if `AUTHPLANE_DEV_MODE=1`. Remove before production. |
| `ClientOptions` | `[]authplane.Option` | no | SDK-level options: `WithClientCredentials`, `WithClientAuthentication`, `WithJWKSCacheTTL`, `WithCircuitBreaker`, `WithDPoP`, etc. |
| `VerifierOptions` | `[]verifier.Option` | no | Verifier-level options: `WithAlgorithms`, `WithClockSkew`, `WithRevocationChecker`, `WithFailClosed`. |

`VerifierOptions` **replaces** the verifier option list set by `client.Resource`. When `ClientOptions` supplies credentials, the SDK auto-wires an introspection-backed revocation checker — if you also pass `VerifierOptions`, include `verifier.WithRevocationChecker(...)` (or `NullRevocationChecker`) explicitly if you want to keep, replace, or disable it.

## 6. Main API reference

### `NewAdapter(ctx context.Context, options Options) (*Adapter, error)`

Constructs an adapter. Performs AS metadata discovery and warms the JWKS cache using `ctx`. Background refresh goroutines use their own context; `ctx` is only for startup.

### `NewAdapterFromClientAndResource(client *authplane.Client, res *resource.Resource) (*Adapter, error)`

Constructs an adapter from an already-built client and resource. Use this when sharing a single client across multiple adapters or when you need full control over construction.

> **Lifecycle note.** `adapter.Close()` calls `client.Close()` regardless of which constructor you used. If you share a client across multiple adapters, do *not* defer `adapter.Close()` on every one — manage `client.Close()` yourself and let the adapters go out of scope.

### `(a *Adapter) AuthMiddleware(handler http.Handler) http.Handler`

Wraps an HTTP handler with bearer-token authentication.

- Rejects unauthenticated requests with 401 and a `WWW-Authenticate` header pointing to the PRM URL.
- On success, injects `*verifier.VerifiedClaims` and the raw token into the request context.
- Internally uses `auth.RequireBearerToken` from the MCP Go SDK so that `auth.TokenInfo` is placed in the context for the streamable transport's session-binding protection.

Scopes are not checked at this layer; tools enforce their own scope (see §4.3).

### `(a *Adapter) ProtectedResourceMetadataHandler() http.Handler`

Serves the RFC 9728 PRM JSON. `GET` only; other methods return 405. Sets `Content-Type: application/json` and `Cache-Control: max-age=3600`.

### `(a *Adapter) WellKnownPRMPath() string`

Returns the well-known PRM path, e.g. `/.well-known/oauth-protected-resource/mcp`.

### `(a *Adapter) TokenExchange(ctx context.Context, input authplane.TokenExchangeInput) (*authplane.TokenResponse, error)`

Performs RFC 8693 token exchange via the underlying client. Automatically maps `*authplane.ConsentRequiredError` with a non-empty `ConsentURL` to `mcp.URLElicitationRequiredError` (see §7). Requires credentials (`WithClientCredentials` or `WithClientAuthentication`) in `ClientOptions`.

### `ConsentElicitationError(err error) error`

Checks whether `err` wraps an `*authplane.ConsentRequiredError` with a non-empty `ConsentURL`; returns `mcp.URLElicitationRequiredError` if so, or the original error otherwise. Use when calling `Client().TokenExchange()` directly and you still want the MCP elicitation mapping.

### `(a *Adapter) Client() *authplane.Client`

Returns the underlying client for operations not exposed on the adapter: `ClientCredentials`, `Revoke`, `Introspect`, `DPoPSigner`. Do not call `Close()` on it — the adapter owns the lifecycle.

### `(a *Adapter) Resource() *resource.Resource`

Returns the underlying resource. Useful for calling `VerifyToken` directly with `resource.WithDPoP(...)` for DPoP-bound flows.

### `(a *Adapter) Close() error`

Stops background refresh goroutines and closes idle HTTP connections. Safe to call more than once.

### `ClaimsFromContext(ctx context.Context) *verifier.VerifiedClaims`

Returns the verified claims injected by `AuthMiddleware`. Returns `nil` outside an authenticated request.

### `TokenFromContext(ctx context.Context) string`

Returns the raw bearer token injected by `AuthMiddleware`. Returns `""` outside an authenticated request.

## 7. Token exchange and URL elicitation

RFC 8693 token exchange frequently runs into an authorization-server response of `consent_required` when the user has not yet granted the requested downstream access. The MCP URL elicitation protocol (JSON-RPC error code `-32042`) lets the server ask the MCP client to open a URL out-of-band — typically a consent page — and retry the original operation once the user is done.

The adapter bridges these two: `adapter.TokenExchange` catches the consent-required error and rewrites it as `mcp.URLElicitationRequiredError` so the MCP client does the right thing automatically.

### 7.1 Automatic mapping

```go
import "github.com/authplane/go-sdk/core/authplane"

mcp.AddTool(server, &mcp.Tool{Name: "calendar/list"},
    func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
        token := authplanemcp.TokenFromContext(ctx)
        resp, err := adapter.TokenExchange(ctx, authplane.TokenExchangeInput{
            SubjectToken: token,
            Scopes:       []string{"calendar.read"},
            Resources:    []string{"https://calendar.example.com/"},
        })
        if err != nil {
            // If the AS returned ConsentRequiredError with a ConsentURL,
            // this is now mcp.URLElicitationRequiredError — the MCP client
            // will prompt the user and retry.
            return nil, nil, err
        }

        // Use resp.AccessToken to call the downstream service.
        _ = resp.AccessToken
        return nil, nil, nil
    },
)
```

The generated `URLElicitationRequiredError` carries:

- The consent URL from the AS response.
- The AS `error_description` as the prompt message (falling back to `"Consent is required to proceed"` when empty).
- A newly minted elicitation ID so the MCP client can correlate the completion event.

If the AS does not provide a `ConsentURL`, the original `*authplane.ConsentRequiredError` is returned unchanged — the tool handler decides how to proceed (abort, fall back to a static message, etc.).

### 7.2 Custom consent handling

When you need custom behavior (e.g. logging, metrics) before mapping:

```go
resp, err := adapter.Client().TokenExchange(ctx, input)
if err != nil {
    // inspect, log, metric...
    return nil, nil, authplanemcp.ConsentElicitationError(err)
}
```

`ConsentElicitationError` performs the same mapping as `adapter.TokenExchange`'s internal path and returns the original error unchanged for anything that isn't a consent-required error with a URL.

### 7.3 No equivalent in the HTTP adapter

URL elicitation is an MCP-protocol concept. The `http` adapter has **no equivalent** — if you run token exchange inside a plain HTTP handler and the AS returns consent-required, you must inspect the error and craft whatever response your API contract calls for (e.g. a 302 to the consent URL, or a JSON envelope). Use `errors.As(err, &consentErr)` against `*authplane.ConsentRequiredError` in that code path.

## 8. Revocation checking

When credentials are supplied in `ClientOptions`, the SDK auto-wires RFC 7662 introspection as the revocation checker. Every successful JWT verification triggers an introspection round-trip; the token is rejected if the AS reports `active: false`.

```go
adapter, err := authplanemcp.NewAdapter(ctx, authplanemcp.Options{
    Issuer:   "https://auth.example.com",
    Resource: "https://mcp.example.com/mcp",
    Scopes:   []string{"tools/query"},
    ClientOptions: []authplane.Option{
        authplane.WithClientCredentials(clientID, clientSecret),
    },
})
```

### 8.1 Disabling introspection

```go
import "github.com/authplane/go-sdk/core/resource/verifier"

adapter, err := authplanemcp.NewAdapter(ctx, authplanemcp.Options{
    // ...
    ClientOptions: []authplane.Option{
        authplane.WithClientCredentials(clientID, clientSecret),
    },
    VerifierOptions: []verifier.Option{
        verifier.WithRevocationChecker(verifier.NullRevocationChecker),
    },
})
```

`NullRevocationChecker` is a pre-built no-op checker. Use it when you want credentials (for token exchange) but not per-request introspection.

### 8.2 Custom revocation checker

```go
VerifierOptions: []verifier.Option{
    verifier.WithRevocationChecker(func(ctx context.Context, claims *verifier.VerifiedClaims, rawToken string) (bool, error) {
        revoked, err := redis.SIsMember(ctx, "revoked_tokens", claims.JTI()).Result()
        return revoked, err
    }),
},
```

By default a checker error is treated as *not revoked* (fail-open). Pair with `verifier.WithFailClosed()` if you want the opposite.

## 9. DPoP (sender-constrained tokens)

Unlike the `http` adapter, `AuthMiddleware` does **not** auto-detect the `DPoP` authorization scheme — the MCP Go SDK's `auth.RequireBearerToken` is Bearer-only. If you need to verify DPoP-bound access tokens on an MCP endpoint, bypass `AuthMiddleware` for that route and call `adapter.Resource().VerifyToken(ctx, token, resource.WithDPoP(dpopCtx))` yourself, following the pattern documented in the [http user guide §7](../../http/docs/user-guide.md#7-dpop-sender-constrained-tokens).

Outbound DPoP (signing token requests to the AS) is configured on the client via `authplane.WithDPoP(km)` and is independent of the MCP middleware — see the [core user guide](../../core/docs/user-guide.md).

## 10. Sharing a pre-built client

```go
client, err := authplane.NewClient(ctx, issuer, authplane.WithClientCredentials(id, secret))
if err != nil {
    return err
}
defer client.Close()

resA, _ := client.Resource("https://mcp.example.com/mcp-a", resource.WithScopes("tools/a"))
resB, _ := client.Resource("https://mcp.example.com/mcp-b", resource.WithScopes("tools/b"))

adapterA, _ := authplanemcp.NewAdapterFromClientAndResource(client, resA)
adapterB, _ := authplanemcp.NewAdapterFromClientAndResource(client, resB)
// Do NOT defer adapterA.Close() or adapterB.Close() — they would both call client.Close().
```

One `*authplane.Client` can back many resources and adapters. When you use `NewAdapterFromClientAndResource`, the adapter still calls `client.Close()` on its own `Close()`, so either:

- Use `adapter.Close()` on exactly one adapter per client, or
- Call `client.Close()` yourself and let adapters go out of scope.

## 11. Development mode

```go
adapter, err := authplanemcp.NewAdapter(ctx, authplanemcp.Options{
    Issuer:   "http://localhost:9000",
    Resource: "http://localhost:8080/mcp",
    Scopes:   []string{"tools/query"},
    DevMode:  true,
})
```

`DevMode: true` relaxes the SDK's SSRF defenses: HTTP (non-TLS) issuers, `localhost`, private networks, and link-local addresses are allowed. It is also honored via the `AUTHPLANE_DEV_MODE=1` environment variable as a fallback.

Do not enable `DevMode` in production. Metadata discovery and JWKS fetching are the primary attack surface the setting loosens.

## 12. Error handling

Errors returned from tool handlers become MCP `isError=true` responses. Errors returned from verification become 401/403/503/500 responses written by the MCP Go SDK's auth middleware (wrapped with `auth.ErrInvalidToken` internally so the status code is right).

When calling `adapter.Client()` operations directly (e.g. `Revoke`, `Introspect`, `ClientCredentials`), you may see any of the OAuth sentinels re-exported from `authplane`:

| Error | Meaning |
|---|---|
| `ErrInvalidGrant` | Subject/actor token invalid or expired. |
| `ErrInvalidScope` | Requested scope exceeds grant. |
| `ErrInvalidClient` | Client authentication failed. |
| `ErrUnauthorizedClient` | Client not authorized for grant type. |
| `ErrUnsupportedGrantType` | Grant type not supported. |
| `ErrInvalidRequest` | Malformed request. |
| `ErrServerError` | AS returned a server error. |
| `ErrCircuitOpen` | Circuit breaker is open; AS recently failed repeatedly. |
| `ErrProtocolError` | Malformed response from AS. |
| `ErrConsentRequired` | User consent required — prefer `*ConsentRequiredError` for the URL. |
| `ErrInteractionRequired` | User interaction required. |
| `ErrUseDPoPNonce` | AS returned a DPoP nonce; the client auto-retries with the nonce. |

The full verifier error list (signature, claims, DPoP, etc.) lives in the [core user guide](../../core/docs/user-guide.md).

## 13. Lifecycle

```go
adapter, err := authplanemcp.NewAdapter(ctx, opts)
if err != nil {
    return err
}
defer adapter.Close() // stops JWKS/metadata refresh goroutines, closes the client
```

`Close()` is safe to call multiple times and always calls `client.Close()`. See §10 for the shared-client nuance.

## 14. See also

- [Core user guide](../../core/docs/user-guide.md) — client, resource, verifier, outbound DPoP, token exchange semantics, full error reference.
- [HTTP adapter user guide](../../http/docs/user-guide.md) — parallel middleware for plain HTTP resource servers, including DPoP inbound verification.
- [`demo/`](../demo/) — runnable Calculator Service with introspection-backed revocation and per-tool scope enforcement.
