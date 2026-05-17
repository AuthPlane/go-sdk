# Authplane HTTP adapter — User Guide

`github.com/authplane/go-sdk/http` provides `net/http` middleware that wraps the [Authplane core SDK](../../core/docs/user-guide.md) so an HTTP resource server can validate Bearer and DPoP access tokens, enforce per-route scopes, and serve RFC 9728 Protected Resource Metadata.

This guide is the thorough reference. The [README](../README.md) holds the hero snippet.

## 1. Install

```bash
go get github.com/authplane/go-sdk/http
```

Requires Go 1.24+. The adapter depends on `github.com/authplane/go-sdk/core`; a compatible `core` version is pulled in transitively.

## 2. Quickstart

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
    defer client.Close()

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
    mux.Handle("/api/", http.HandlerFunc(readHandler))

    http.ListenAndServe(":8080", adapter.Middleware()(mux))
}
```

## 3. Core concepts

The HTTP adapter is a **thin wrapper around `*resource.Resource`**. It does not own client lifecycle — the caller constructs and closes the `*authplane.Client`. One client typically backs many resources and adapters in a single process.

Three things happen per request when the adapter is mounted:

1. `Middleware()` extracts the `Authorization` header, verifies the token (Bearer or DPoP), and injects `*verifier.VerifiedClaims` plus the raw token into the request context.
2. `RequireScopes(...)` middleware (optional, per-route) checks the claims for required scopes.
3. The well-known PRM path is auto-excluded from token checks so unauthenticated clients can discover the authorization server and scopes.

On failure, the adapter writes an RFC 6750 error response: correct HTTP status, `WWW-Authenticate` header with the right scheme (`Bearer` or `DPoP`), error code, and JSON body.

## 4. Basic usage

### 4.1 Construct the adapter

```go
adapter := authplanehttp.New(res)
```

`res` must be a `*resource.Resource` created via `client.Resource(uri, resource.WithScopes(...))`. The adapter is safe for concurrent use and holds no cleanup state of its own; the client (returned by `authplane.NewClient`) is what needs `Close()`.

### 4.2 Mount middleware

```go
mux := http.NewServeMux()
mux.Handle(adapter.WellKnownPRMPath(), adapter.PRMHandler())

// ... add your application routes to mux ...

// Wrap everything with the auth middleware.
http.ListenAndServe(":8080", adapter.Middleware()(mux))
```

The PRM handler must be registered on the path returned by `WellKnownPRMPath()`. `Middleware()` automatically passes that path through without requiring a token.

### 4.3 Per-route scope enforcement

```go
mux.Handle("/api/admin", adapter.RequireScopes("admin")(adminHandler))
mux.Handle("/api/reports", adapter.RequireScopes("reports.read", "reports.write")(reportsHandler))
```

`RequireScopes(...)` must sit *inside* `Middleware()` (i.e. the outer middleware runs first). If no claims are in context when `RequireScopes` runs, it writes a 401 — the signal that `Middleware()` was forgotten. If a required scope is missing, it writes a 403 with `WWW-Authenticate: Bearer error="insufficient_scope", scope="admin"`.

### 4.4 Read claims and the raw token

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    claims := authplanehttp.ClaimsFromContext(r.Context())
    // claims.Sub(), claims.ClientID(), claims.Scopes(), claims.HasScope("x"), etc.

    token := authplanehttp.TokenFromContext(r.Context())
    // Useful when the handler needs to forward, exchange, or revoke the incoming token.
}
```

Both helpers return the zero value (nil / empty string) if called outside an authenticated request, so handlers wired only after `Middleware()` can rely on `claims != nil`.

## 5. Main API reference

### `New(res *resource.Resource, opts ...Option) *Adapter`

Creates an adapter wrapping the given resource. Accepts zero or more `Option` values (see §6).

### `(a *Adapter) Middleware() func(http.Handler) http.Handler`

Standard `net/http` middleware.

- Extracts the `Authorization` header. Supports `Bearer` and `DPoP` schemes (case-insensitive).
- For `DPoP`, also consumes the `DPoP` request header and constructs a `*verifier.DPoPContext` with the request method, reconstructed URL (scheme + host + request URI), proof, and the adapter's replay store.
- Calls `resource.VerifyToken(ctx, token, opts...)`.
- On success, injects `*verifier.VerifiedClaims` and the raw token into the request context.
- On failure, writes an RFC 6750 response via `resource.AuthErrorResponse`.
- Requests whose path equals `WellKnownPRMPath()` are passed through unauthenticated.

### `(a *Adapter) RequireScopes(scopes ...string) func(http.Handler) http.Handler`

Per-route scope enforcement. Wraps a handler and checks that every scope in `scopes` is present on the authenticated claims.

- Returns 401 (via `ErrTokenMissing`) if no claims are in context — indicates `Middleware()` was not applied upstream.
- Returns 403 (via `ScopeError{RequiredScopes: scopes, Err: ErrInsufficientScope}`) on the first missing scope; the `WWW-Authenticate` header includes a `scope=` parameter listing all required scopes.

### `(a *Adapter) PRMHandler() http.Handler`

Serves the RFC 9728 Protected Resource Metadata JSON. Responds only to `GET`; other methods return 405. Sets `Content-Type: application/json` and `Cache-Control: max-age=3600`.

### `(a *Adapter) WellKnownPRMPath() string`

Returns the well-known path for the resource, e.g. `/.well-known/oauth-protected-resource/api`. Path is derived from the resource URI's path component.

### `ClaimsFromContext(ctx context.Context) *verifier.VerifiedClaims`

Returns the verified claims injected by `Middleware()`. Returns `nil` outside an authenticated request.

### `TokenFromContext(ctx context.Context) string`

Returns the raw bearer token injected by `Middleware()`. Returns `""` outside an authenticated request.

## 6. Configuration

The HTTP adapter has no options of its own. All resource-level policy — including DPoP replay store, accepted proof algorithms, proof age, clock skew, and whether DPoP is required — is configured on the `*resource.Resource` you pass in via `verifier.WithInboundDPoP`. See the [core user guide](../../core/docs/user-guide.md) for those.

```go
res, err := client.Resource("https://api.example.com",
    resource.WithVerifierOptions(verifier.WithInboundDPoP(verifier.InboundDPoPOptions{
        ReplayStore: verifier.NewInMemoryDPoPReplayStore(),
        Required:    true,
    })),
)
adapter := authplanehttp.New(res)
```

## 7. DPoP (sender-constrained tokens)

The adapter auto-detects the `DPoP` authorization scheme. When it sees `Authorization: DPoP <token>`, it:

1. Reads the `DPoP` request header (the proof JWT).
2. Reconstructs the request URL from `r.TLS`, `r.Host`, and `r.URL.RequestURI()`.
3. Passes a `*verifier.DPoPContext` carrying only `{Method, URL, Proof}` into `resource.VerifyToken`.

The verifier enforces proof signature, `htm`/`htu`/`ath` checks, the `cnf.jkt` binding on the access token, and (when an `InboundDPoPOptions.ReplayStore` is configured) replay protection.

Errors surface through the normal middleware path:

- `ErrDPoPRequired` — resource requires DPoP but the request did not satisfy it → 401, `WWW-Authenticate: DPoP`.
- `ErrDPoPNotSupported` — resource is not configured for DPoP but the access token is sender-bound → 401, `WWW-Authenticate: Bearer`.
- `ErrDPoPInvalid` — proof signature, `htm`, `htu`, `ath`, or `iat` failed → 401, `WWW-Authenticate: DPoP`.
- `ErrDPoPKeyMismatch` — proof thumbprint does not match `cnf.jkt` → 401, `WWW-Authenticate: DPoP`.
- `ErrDPoPReplayDetected` — JTI previously seen → 401, `WWW-Authenticate: DPoP`.

### 7.1 Running behind a TLS-terminating proxy

`Middleware()` builds the URL with `https` if `r.TLS != nil`, otherwise `http`. If you terminate TLS upstream, the proof's `htu` must match the URL seen by the handler — configure your reverse proxy to forward the original host and scheme, or set them explicitly on the request before the middleware runs. The standard `X-Forwarded-*` handling is the caller's responsibility; the adapter does not parse those headers.

## 8. Replay stores

A replay store is a `verifier.DPoPReplayStore` provided through `verifier.WithInboundDPoP`. The HTTP adapter does not own replay state.

### 8.1 In-memory store

```go
client.Resource(uri,
    resource.WithVerifierOptions(verifier.WithInboundDPoP(verifier.InboundDPoPOptions{
        ReplayStore: verifier.NewInMemoryDPoPReplayStore(),
    })),
)
```

Safe for concurrent use. Not safe across replicas: a proof rejected on replica A is unknown to replica B.

### 8.2 Custom distributed store

Implement `verifier.DPoPReplayStore`:

```go
type DPoPReplayStore interface {
    CheckAndStore(jti string, expiresAt time.Time) (stored bool, err error)
}
```

A minimal Redis sketch:

```go
type RedisReplayStore struct{ client *redis.Client }

func (s *RedisReplayStore) CheckAndStore(jti string, expiresAt time.Time) (bool, error) {
    ttl := time.Until(expiresAt)
    if ttl <= 0 {
        return true, nil // already expired; treat as stored, verifier will reject on exp
    }
    ok, err := s.client.SetNX(context.Background(), "dpop:"+jti, "1", ttl).Result()
    return ok, err
}

client.Resource(uri,
    resource.WithVerifierOptions(verifier.WithInboundDPoP(verifier.InboundDPoPOptions{
        ReplayStore: &RedisReplayStore{client: rdb},
    })),
)
```

`CheckAndStore` must be atomic: two concurrent calls for the same `jti` must have exactly one return `stored=true`.

## 9. Error handling

The middleware maps every verifier error to an RFC 6750 response via `resource.AuthErrorResponse`. If you need to handle errors yourself inside a custom middleware chain, call the same helpers:

```go
import "github.com/authplane/go-sdk/core/resource"

status := resource.HTTPStatus(err)
status, headers, body := resource.AuthErrorResponse(err)
```

Status mapping (from `resource.HTTPStatus`):

| Error | HTTP |
|---|---|
| `ErrTokenMissing`, `ErrTokenExpired`, `ErrInvalidSignature`, `ErrInvalidClaims`, `ErrIssuerMismatch`, `ErrAudienceMismatch`, `ErrTokenRevoked`, `ErrDPoPRequired`, `ErrDPoPInvalid`, `ErrDPoPKeyMismatch`, `ErrDPoPReplayDetected` | 401 |
| `ErrInsufficientScope` | 403 |
| `ErrJWKSUnavailable`, `ErrMetadataUnavailable` | 503 |
| `ErrSSRFBlocked`, `ErrProtocolError`, other | 500 |

`WWW-Authenticate` scheme is `DPoP` for any DPoP error and `Bearer` otherwise. The full error reference lives in the [core user guide](../../core/docs/user-guide.md).

## 10. Lifecycle

The adapter itself does not hold background resources — it is stateless apart from the replay store. Cleanup lives on the `*authplane.Client`:

```go
client, err := authplane.NewClient(ctx, issuer, ...)
if err != nil {
    return err
}
defer client.Close() // stops JWKS refresh goroutines, closes idle HTTP connections
```

If you provide a custom `DPoPReplayStore` with its own resources (connection pools, background sweeps), close it on the same path you close the client.

## 11. See also

- [Core user guide](../../core/docs/user-guide.md) — client, resource, verifier, errors, DPoP outbound signing, token exchange.
- [MCP adapter user guide](../../mcp/docs/user-guide.md) — same ideas, MCP-specific middleware and URL elicitation for consent flows.
- [`demo/`](../demo/) — runnable Calculator Service that exercises introspection-backed revocation and per-route scope enforcement.
