# Authplane HTTP adapter — User Guide

`github.com/authplane/go-sdk/http` provides `net/http` middleware that wraps the [Authplane core SDK](../../core/docs/user-guide.md) so an HTTP resource server can validate Bearer and DPoP access tokens, enforce per-route scopes, and serve RFC 9728 Protected Resource Metadata.

This guide is the thorough reference. The [README](../README.md) holds the hero snippet.

## 1. Install

```bash
go get github.com/authplane/go-sdk/http
```

Requires Go 1.26+. The adapter depends on `github.com/authplane/go-sdk/core`; a compatible `core` version is pulled in transitively.

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

    adapter, err := authplanehttp.New(res)
    if err != nil {
        panic(err)
    }

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
adapter, err := authplanehttp.New(res)
if err != nil {
    panic(err)
}
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
- On failure, writes an RFC 6750 response via `resource.AuthErrorResponse`, whose challenge carries `resource_metadata="…"` (RFC 9728 §5.1) pointing at `res.ResourceMetadataURL()` — see §6.1.
- A 401 also carries `scope="…"` listing the resource's configured scopes (`resource.WithScopes`), per RFC 6750 §3 and the MCP authorization spec's SHOULD, so a client learns what to request before it holds any token — e.g. `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp", scope="tools/add tools/multiply"`. The param is omitted when no scopes are configured. A 403 from `RequireScopes` keeps its own route-specific `scope=` (below) and is not touched.
- Requests whose **escaped** path (`r.URL.EscapedPath()`) equals `WellKnownPRMPath()` are passed through unauthenticated. The comparison is on the escaped form on both sides: a resource identifier carrying a percent-encoded octet (e.g. `%2F`) derives a well-known path that keeps it, and comparing the decoded `r.URL.Path` would let `%2F` collapse to `/`, disagree, and return 401 for the discovery endpoint RFC 9728 §3.2 requires to be publicly reachable.

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
adapter, err := authplanehttp.New(res)
if err != nil {
    panic(err)
}
```

### 6.1 Where the PRM document lives

RFC 9728 admits two topologies, and the adapter serves both.

**(a) Resource-hosted — the default.** The SDK derives `/.well-known/oauth-protected-resource[/path]` from the resource identifier, `PRMHandler()` serves the document, and the `WWW-Authenticate` challenge advertises that URL. Nothing to configure.

**(b) AS-hosted.** authserver 0.2.0 and later publishes a document for every registered Resource at `<issuer>/.well-known/oauth-protected-resource/{ref}`, where `{ref}` is the RFC 9728 §3.1 path suffix of the Resource URI (or its slug). Point the challenge there when the resource server cannot host well-known paths — a platform that owns `/.well-known`, a proxy that will not forward it:

```go
res, err := client.Resource("https://api.example.com/mcp",
    resource.WithScopes("read", "write"),
    resource.WithResourceMetadataURL("https://auth.example.com/.well-known/oauth-protected-resource/mcp"),
)
adapter, err := authplanehttp.New(res)
if err != nil {
    panic(err)
}
```

Only the advertisement moves. `WellKnownPRMPath()` and `PRMHandler()` keep serving the derived route, so you can switch the pointer first and retire the local endpoint afterwards. The URL is validated at construction: absolute, `https` or `http`, no fragment, no userinfo.

Whichever topology you use, RFC 9728 §3.3 pins the same constraint: the `resource` member inside the document must equal the URL clients call, byte for byte — a client must discard a document whose `resource` differs from the identifier it derived the request from. So the Resource URI registered at the authorization server, the identifier you configure here, and the public URL your server is reached on must be one and the same string, trailing slash and port included.

## 7. DPoP (sender-constrained tokens)

The adapter auto-detects the `DPoP` authorization scheme. When it sees `Authorization: DPoP <token>`, it:

1. Reads the `DPoP` request header (the proof JWT).
2. Builds the request URL from the configured resource URI and the request path, never from `r.TLS` or `r.Host`.
3. Passes a `*verifier.DPoPContext` carrying only `{Method, URL, Proof}` into `resource.VerifyToken`.

The verifier enforces proof signature, `htm`/`htu`/`ath` checks, the `cnf.jkt` binding on the access token, and replay protection, through `InboundDPoPOptions.ReplayStore` or an in-memory store, unless `DisableReplayCheck` is set.

Errors surface through the normal middleware path:

- `ErrDPoPRequired` — resource requires DPoP but the request did not satisfy it → 401, `WWW-Authenticate: DPoP`.
- `ErrDPoPNotSupported` — resource is not configured for DPoP but the access token is sender-bound → 401, `WWW-Authenticate: Bearer`.
- `ErrDPoPInvalid` — proof signature, `htm`, `htu`, `ath`, or `iat` failed → 401, `WWW-Authenticate: DPoP`.
- `ErrDPoPKeyMismatch` — proof thumbprint does not match `cnf.jkt` → 401, `WWW-Authenticate: DPoP`.
- `ErrDPoPReplayDetected` — JTI previously seen → 401, `WWW-Authenticate: DPoP`.

### 7.1 Running behind a TLS-terminating proxy

`Middleware()` builds the URL for the `htu` comparison from the configured resource URI, never from `r.TLS` or the `Host` header, which a proxy or a client can change. So the resource URI must be the public origin clients call. Only the path comes from the request, so mount the middleware where it sees the path the client signed, before any `http.StripPrefix`.

## 8. Replay stores

A replay store is a `verifier.DPoPReplayStore` provided through `verifier.WithInboundDPoP`. With none, an in-memory store is used, which suits a single instance. `DisableReplayCheck: true` turns the check off. The HTTP adapter does not own replay state.

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

The middleware maps every verifier error to an RFC 6750 response via `resource.AuthErrorResponse`. If you need to handle errors yourself inside a custom middleware chain, call the same helper — it returns the status too, so there is no need to call `HTTPStatus` as well:

```go
import "github.com/authplane/go-sdk/core/resource"

// status, WWW-Authenticate + Content-Type headers, and the JSON body:
status, headers, body := res.AuthErrorResponse(err, resource.WithChallengeMetadata(res.ResourceMetadataURL()))
```

`WithChallengeMetadata` appends the RFC 9728 §5.1 `resource_metadata` parameter to the challenge — pass `res.ResourceMetadataURL()` and your custom middleware advertises the same document the adapter does. `resource.AuthErrorResponse(err)` is the same call without that parameter.

Status mapping (from `resource.HTTPStatus`):

| Error | HTTP |
|---|---|
| `ErrTokenMissing`, `ErrTokenExpired`, `ErrInvalidSignature`, `ErrInvalidClaims`, `ErrIssuerMismatch`, `ErrAudienceMismatch`, `ErrTokenRevoked`, `ErrDPoPRequired`, `ErrDPoPInvalid`, `ErrDPoPKeyMismatch`, `ErrDPoPReplayDetected` | 401 |
| `ErrInsufficientScope` | 403 |
| `ErrJWKSUnavailable`, `ErrMetadataUnavailable`, `ErrRevocationUnavailable`, `ErrDPoPReplayStoreUnavailable` | 503 |
| other | 500 |

`WWW-Authenticate` scheme is `DPoP` for any DPoP error and `Bearer` otherwise. A bad, replayed or wrong-key proof answers `invalid_dpop_proof`, DPoP challenges list `algs`, and a resource requiring DPoP answers a request with no token with the `DPoP` scheme. A 503 has no `error` in its challenge, a `temporarily_unavailable` body and `Retry-After`: keep the token and retry. The JSON body's `error_description` is a fixed sentence chosen by the error code, never the verifier's own message. The adapter owns the error at that point and no longer returns it, so it writes the diagnostic to `slog.Default()`, at Error for a 5xx and otherwise at DEBUG (`authplane: rejecting request`, with `err` and `status`); enable debug logging on your default handler to see it, or call `resource.VerifyToken` directly if you want the error in hand. The full error reference lives in the [core user guide](../../core/docs/user-guide.md).

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

## Other authorization servers

This adapter takes the server-neutral options of `core` through `resource.WithVerifierOptions`: `WithAcceptedTokenTypes`, `WithRequiredClaims`, `WithScopeClaims`, `WithClientClaims`, `WithAccessTokenMarkers` and `WithExpectedAudience`. See [Using another authorization server](../../core/docs/user-guide.md#using-another-authorization-server).
