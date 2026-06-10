# Authplane mark3labs/mcp-go adapter — User Guide

`github.com/authplane/go-sdk/mark3labs` is a thin adapter between the [Authplane core SDK](../../core/docs/user-guide.md) and [`github.com/mark3labs/mcp-go`](https://github.com/mark3labs/mcp-go). It validates OAuth 2.1 JWT access tokens on MCP server requests, serves RFC 9728 Protected Resource Metadata, and bridges RFC 8693 token-exchange consent errors to the MCP URL elicitation shape (JSON-RPC `-32042`).

This guide is the thorough reference. The [README](../README.md) holds the hero snippet.

## 1. Install

```bash
go get github.com/authplane/go-sdk/mark3labs
```

Requires Go 1.25.5+ (the minimum mark3labs/mcp-go v0.54.0 needs). Also pulls in `github.com/authplane/go-sdk/core` and `github.com/mark3labs/mcp-go`.

## 2. Quickstart

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
    defer adapter.Close()

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

## 3. Core concepts

`NewAdapter` constructs and owns an `*authplane.Client` and a `*resource.Resource`:

1. `authplane.NewClient` performs RFC 8414 AS metadata discovery.
2. `client.Resource(uri, resource.WithScopes(...))` builds the resource (the JWKS cache is warmed and background refresh starts).
3. If `ClientOptions` includes `WithClientCredentials` or `WithClientAuthentication`, RFC 7662 introspection is auto-wired as the revocation checker, and `TokenExchange` becomes operational.

Internally `*Adapter` embeds [`*authplanehttp.Adapter`](../../http/docs/user-guide.md) — the generic Authplane net/http adapter — so the Bearer/DPoP middleware, scope-enforcing middleware, context helpers, and RFC 6750 / RFC 9728 `WWW-Authenticate` response (including `resource_metadata="..."` advertisement) all come from one shared implementation rather than being re-implemented per adapter. mark3labs-only additions are the context bridge and the URL-elicitation mapping.

The adapter integrates with mark3labs/mcp-go through **two coordinated hooks**:

| Hook | Purpose |
|---|---|
| `adapter.AuthMiddleware(next)` | Standard `http.Handler` middleware (delegates to `authplanehttp.Middleware()`). Parses `Authorization: Bearer …` *or* `Authorization: DPoP …`, runs the verifier, and on success stores `*verifier.VerifiedClaims` plus the raw token in the **HTTP request** context. On failure it writes a 401 with an RFC 6750 §3.1 compliant `WWW-Authenticate` header that advertises the PRM URL via `resource_metadata=` (RFC 9728 §5.1). The PRM well-known path is auto-excluded from authentication. |
| `server.WithHTTPContextFunc(adapter.HTTPContextFunc())` | Forwards claims/token from the HTTP request context into the **per-tool-call** MCP context. Without it, tool handlers receive a fresh context with no claims. |

Scope enforcement is **per-tool**, not per-request. The middleware itself accepts any valid token; individual tool handlers call `ClaimsFromContext(ctx).RequireScope(...)`. This matches the MCP protocol: `initialize` and protocol-level messages must succeed with any authenticated client.

## 4. Basic usage

### 4.1 Construct the adapter

```go
adapter, err := authplanemark3labs.NewAdapter(ctx, authplanemark3labs.Options{
    Issuer:   "https://auth.example.com",
    Resource: "https://mcp.example.com/mcp",
    Scopes:   []string{"tools/query"},
})
```

All three fields are required. The `Scopes` slice is advertised in the PRM document; it does **not** enforce that every token carries all listed scopes — individual tools decide what they need.

### 4.2 Mount the handlers

```go
mcpServer := server.NewMCPServer("My Server", "1.0.0",
    server.WithToolCapabilities(false),
    server.WithRecovery(),
)
streamable := server.NewStreamableHTTPServer(mcpServer,
    server.WithHTTPContextFunc(adapter.HTTPContextFunc()),
)

http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
http.Handle("/mcp", adapter.AuthMiddleware(streamable))
```

PRM is always served unauthenticated. `AuthMiddleware` wraps the streamable HTTP server.

> **Don't use `server.WithProtectedResourceMetadata(...)`** for this adapter. That option only takes effect when the streamable server owns the top-level mux (i.e. when you call `streamable.Start()`); with a custom router, PRM never gets registered. `adapter.ProtectedResourceMetadataHandler()` wraps mark3labs/mcp-go's `server.NewProtectedResourceMetadataHandler` and is mounted on your outer router so it stays reachable independently of the auth-wrapped MCP endpoint.

### 4.3 Enforce scope inside tool handlers

```go
import (
    "github.com/authplane/go-sdk/core/resource/verifier"
    "github.com/mark3labs/mcp-go/mcp"
    "github.com/mark3labs/mcp-go/server"
)

addTool := mcp.NewTool("add",
    mcp.WithDescription("Add two numbers"),
    mcp.WithNumber("a", mcp.Required(), mcp.Description("First addend")),
    mcp.WithNumber("b", mcp.Required(), mcp.Description("Second addend")),
)

mcpServer.AddTool(addTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    claims := authplanemark3labs.ClaimsFromContext(ctx)
    if claims == nil {
        return mcp.NewToolResultError(verifier.ErrTokenMissing.Error()), nil
    }
    if err := claims.RequireScope("tools/add"); err != nil {
        return mcp.NewToolResultError(err.Error()), nil
    }
    a, _ := request.RequireFloat("a")
    b, _ := request.RequireFloat("b")
    return mcp.NewToolResultText(fmt.Sprintf("%g", a+b)), nil
})
```

`claims` is never nil when the tool is reached through `AuthMiddleware` + `WithHTTPContextFunc`, but the guard is cheap and makes the handler robust when called from other code paths (tests, direct invocations).

Why `mcp.NewToolResultError(...)` instead of returning `err`? mark3labs/mcp-go coerces every error returned from a tool handler to JSON-RPC `-32603` (INTERNAL_ERROR), so an `IsError: true` result is the only way to surface a structured failure with a useful message to the client.

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

Constructs an adapter from an already-built client and resource. Use this when sharing a single client across multiple adapters or when you need full control over construction. Returns an error if `client` is nil.

> **Lifecycle note.** `adapter.Close()` calls `client.Close()` regardless of which constructor you used. If you share a client across multiple adapters, do *not* defer `adapter.Close()` on every one — manage `client.Close()` yourself and let the adapters go out of scope.

### `(a *Adapter) AuthMiddleware(handler http.Handler) http.Handler`

Wraps an HTTP handler with Bearer (and DPoP) token authentication. Equivalent to `a.Middleware()(handler)`; the call shape is preserved for fluency in mark3labs code.

- Rejects unauthenticated requests with 401 and a `WWW-Authenticate: Bearer resource_metadata="…"` header (RFC 9728 §5.1).
- Rejects invalid Bearer tokens with 401 + `error="invalid_token"`; DPoP-bound errors return the `DPoP` scheme as required by RFC 9449.
- On success, injects `*verifier.VerifiedClaims` and the raw token into the request context.
- The PRM well-known path is auto-excluded so the metadata endpoint stays publicly reachable even when this middleware wraps a broad route prefix.

Scopes are not checked at this layer; tools enforce their own scope (see §4.3).

### Inherited from `*authplanehttp.Adapter`

Because `*Adapter` embeds `*authplanehttp.Adapter`, the following methods from the http adapter are available directly:

- `Middleware() func(http.Handler) http.Handler` — the underlying middleware (`AuthMiddleware` is a one-line wrapper).
- `PRMHandler() http.Handler` — the plain-HTTP PRM handler (`max-age=3600`, no CORS). Prefer `ProtectedResourceMetadataHandler()` below for MCP clients.
- `WellKnownPRMPath() string` — the RFC 9728 well-known path.
- `RequireScopes(scopes ...string) func(http.Handler) http.Handler` — RFC 6750 `insufficient_scope` middleware (useful for non-MCP HTTP routes mounted alongside `/mcp`).

### `(a *Adapter) HTTPContextFunc(opts ...HTTPContextOption) server.HTTPContextFunc`

Returns a `server.HTTPContextFunc` to pass to `server.WithHTTPContextFunc(...)` on the streamable server. Copies the claims and raw token from the HTTP request context (set by `AuthMiddleware`) into the context that mark3labs/mcp-go uses as the parent for tool-call contexts.

By default only the auth pair is forwarded — values placed on the upstream request context by other middleware (tracing spans, request IDs, etc.) are dropped on the MCP context. Use the options below to forward more:

- `WithForwardedContextKeys(keys ...any)` — copy the listed keys from the upstream request context onto the MCP context. Suitable for upstream middleware that exposes its context key publicly:

  ```go
  type ctxKey string
  const requestIDKey ctxKey = "request-id"

  server.WithHTTPContextFunc(adapter.HTTPContextFunc(
      authplanemark3labs.WithForwardedContextKeys(requestIDKey),
  ))
  ```

- `WithContextForwarding(func(parent, mcp context.Context) context.Context)` — escape hatch for libraries whose context key is unexported (e.g. OpenTelemetry's span context). The function receives the upstream request context and the MCP context already populated with claims/token, and returns a context derived from the MCP one. Multiple options compose in registration order.

  ```go
  server.WithHTTPContextFunc(adapter.HTTPContextFunc(
      authplanemark3labs.WithContextForwarding(func(parent, mcp context.Context) context.Context {
          return trace.ContextWithSpanContext(mcp, trace.SpanContextFromContext(parent))
      }),
  ))
  ```

### `(a *Adapter) ProtectedResourceMetadataHandler() http.Handler`

Returns mark3labs/mcp-go's `server.NewProtectedResourceMetadataHandler` configured from `core`'s `resource.PRMResponse()`. The values (`resource`, `authorization_servers`, `bearer_methods_supported`, `scopes_supported`, DPoP fields) come from `core` so they stay aligned with what other Authplane adapters advertise; HTTP framing is mark3labs/mcp-go's (per RFC 9728 / the MCP authorization spec):

- `GET` and `HEAD` return the metadata JSON.
- `OPTIONS` returns 204 (CORS preflight).
- Other methods return 405 with an `Allow` header.
- Permissive CORS (`Access-Control-Allow-Origin: *`) and `Cache-Control: no-store` are always set.

### `(a *Adapter) TokenExchange(ctx context.Context, input authplane.TokenExchangeInput) (*authplane.TokenResponse, error)`

Performs RFC 8693 token exchange via the underlying client. Automatically maps `*authplane.ConsentRequiredError` with a non-empty `ConsentURL` to `*URLElicitationError` (see §7). Requires credentials (`WithClientCredentials` or `WithClientAuthentication`) in `ClientOptions`.

### `ConsentElicitationError(err error) error`

Checks whether `err` wraps an `*authplane.ConsentRequiredError` with a non-empty `ConsentURL`; returns `*URLElicitationError` if so, or the original error otherwise. Use when calling `Client().TokenExchange()` directly and you still want the mapping.

### `URLElicitationError`

Typed error carrying the URL elicitation payload (`mcp.ElicitationParams` with `Mode="url"`). `Code()` returns `mcp.URL_ELICITATION_REQUIRED` (-32042). `MarshalData()` returns the JSON payload suitable for the `data` field of a JSON-RPC `-32042` error.

### `(a *Adapter) Client() *authplane.Client`

Returns the underlying client for operations not exposed on the adapter: `ClientCredentials`, `Revoke`, `Introspect`, `DPoPSigner`. Do not call `Close()` on it — the adapter owns the lifecycle.

### `(a *Adapter) Resource() *resource.Resource`

Returns the underlying resource. Useful for calling `VerifyToken` directly with `resource.WithDPoP(...)` for DPoP-bound flows.

### `(a *Adapter) Close() error`

Stops background refresh goroutines and closes idle HTTP connections. Safe to call more than once.

### `ClaimsFromContext(ctx context.Context) *verifier.VerifiedClaims`

Returns the verified claims forwarded by `HTTPContextFunc`. Returns `nil` outside an authenticated request.

### `TokenFromContext(ctx context.Context) string`

Returns the raw bearer token forwarded by `HTTPContextFunc`. Returns `""` outside an authenticated request.

## 7. Token exchange and URL elicitation

RFC 8693 token exchange frequently runs into an authorization-server response of `consent_required` when the user has not yet granted the requested downstream access. The MCP URL elicitation protocol (JSON-RPC error code `-32042`) lets the server ask the MCP client to open a URL out-of-band — typically a consent page — and retry the original operation once the user is done.

### 7.1 Detecting consent errors

```go
import "github.com/authplane/go-sdk/core/authplane"

resp, err := adapter.TokenExchange(ctx, authplane.TokenExchangeInput{
    SubjectToken: authplanemark3labs.TokenFromContext(ctx),
    Scopes:       []string{"calendar.read"},
    Resources:    []string{"https://calendar.example.com/"},
})
if err != nil {
    var elic *authplanemark3labs.URLElicitationError
    if errors.As(err, &elic) {
        // Build an isError CallToolResult that carries the elicitation data —
        // see §7.2 for the propagation caveat.
        data, _ := elic.MarshalData()
        return mcp.NewToolResultErrorFromErr(elic.Error(), errors.New(string(data))), nil
    }
    return mcp.NewToolResultErrorFromErr("token exchange failed", err), nil
}
```

### 7.2 Propagation caveat

mark3labs/mcp-go coerces every error returned from a tool handler to JSON-RPC `-32603` (INTERNAL_ERROR); custom JSON-RPC error codes are **not** propagated from tool handlers as of v0.54.0. That means returning `*URLElicitationError` from a tool handler will not produce a `-32042` JSON-RPC error on the wire — the client will see a generic internal error instead.

Two workarounds are practical today:

1. **Return an `IsError: true` `CallToolResult`** carrying the consent URL in the result content. The client receives a successful JSON-RPC response with `result.isError=true` and can interpret the URL out-of-band.
2. **Intercept errors at the streamable transport layer** with a custom wrapper that serialises `*URLElicitationError` into a proper JSON-RPC `-32042` response before mark3labs/mcp-go writes its own response. This requires either a fork or upstream support.

This is a property of mark3labs/mcp-go v0.54.0's tool-call error path, not of this adapter; track upstream for changes.

### 7.3 Custom consent handling

When you need custom behavior (e.g. logging, metrics) before the mapping:

```go
resp, err := adapter.Client().TokenExchange(ctx, input)
if err != nil {
    // inspect, log, metric...
    return nil, authplanemark3labs.ConsentElicitationError(err)
}
```

`ConsentElicitationError` performs the same mapping as `adapter.TokenExchange`'s internal path and returns the original error unchanged for anything that isn't a consent-required error with a URL.

## 8. Revocation checking

When credentials are supplied in `ClientOptions`, the SDK auto-wires RFC 7662 introspection as the revocation checker. Every successful JWT verification triggers an introspection round-trip; the token is rejected if the AS reports `active: false`.

```go
adapter, err := authplanemark3labs.NewAdapter(ctx, authplanemark3labs.Options{
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

adapter, err := authplanemark3labs.NewAdapter(ctx, authplanemark3labs.Options{
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

`AuthMiddleware` accepts both `Authorization: Bearer …` and `Authorization: DPoP …` schemes — that comes from the embedded `*authplanehttp.Adapter`. Inbound DPoP policy (replay store, proof age, allowed algorithms, required flag) is configured on the wrapped `*resource.Resource` via `verifier.WithInboundDPoP(...)` passed in `Options.VerifierOptions`. See the [http user guide §7](../../http/docs/user-guide.md#7-dpop-sender-constrained-tokens) for the full DPoP recipe; everything there applies here.

Outbound DPoP (signing token requests to the AS) is configured on the client via `authplane.WithDPoP(km)` in `Options.ClientOptions` and is independent of the inbound middleware — see the [core user guide](../../core/docs/user-guide.md).

## 10. Sharing a pre-built client

```go
client, err := authplane.NewClient(ctx, issuer, authplane.WithClientCredentials(id, secret))
if err != nil {
    return err
}
defer client.Close()

resA, _ := client.Resource("https://mcp.example.com/mcp-a", resource.WithScopes("tools/a"))
resB, _ := client.Resource("https://mcp.example.com/mcp-b", resource.WithScopes("tools/b"))

adapterA, _ := authplanemark3labs.NewAdapterFromClientAndResource(client, resA)
adapterB, _ := authplanemark3labs.NewAdapterFromClientAndResource(client, resB)
// Do NOT defer adapterA.Close() or adapterB.Close() — they would both call client.Close().
```

One `*authplane.Client` can back many resources and adapters. When you use `NewAdapterFromClientAndResource`, the adapter still calls `client.Close()` on its own `Close()`, so either:

- Use `adapter.Close()` on exactly one adapter per client, or
- Call `client.Close()` yourself and let adapters go out of scope.

## 11. Development mode

```go
adapter, err := authplanemark3labs.NewAdapter(ctx, authplanemark3labs.Options{
    Issuer:   "http://localhost:9000",
    Resource: "http://localhost:8080/mcp",
    Scopes:   []string{"tools/query"},
    DevMode:  true,
})
```

`DevMode: true` relaxes the SDK's SSRF defenses: HTTP (non-TLS) issuers, `localhost`, private networks, and link-local addresses are allowed. It is also honored via the `AUTHPLANE_DEV_MODE=1` environment variable as a fallback.

Do not enable `DevMode` in production. Metadata discovery and JWKS fetching are the primary attack surface the setting loosens.

## 12. Error handling

Verifier failures during `AuthMiddleware` become 401 responses with a proper `WWW-Authenticate` challenge. Errors returned from tool handlers become JSON-RPC `-32603` regardless of type (see §7.2); prefer `IsError: true` `CallToolResult` for structured tool failures.

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
adapter, err := authplanemark3labs.NewAdapter(ctx, opts)
if err != nil {
    return err
}
defer adapter.Close() // stops JWKS/metadata refresh goroutines, closes the client
```

`Close()` is safe to call multiple times and always calls `client.Close()`. See §10 for the shared-client nuance.

## 14. See also

- [Core user guide](../../core/docs/user-guide.md) — client, resource, verifier, outbound DPoP, token exchange semantics, full error reference.
- [Official MCP Go SDK adapter](../../mcp/docs/user-guide.md) — same SDK, different MCP library (`modelcontextprotocol/go-sdk`). Use that one if you're already on the official SDK.
- [HTTP adapter user guide](../../http/docs/user-guide.md) — parallel middleware for plain HTTP resource servers, including DPoP inbound verification.
- [`demo/`](../demo/) — runnable Calculator Service with introspection-backed revocation and per-tool scope enforcement.
