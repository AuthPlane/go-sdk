# Authplane mark3labs/mcp-go adapter — User Guide

`github.com/authplane/go-sdk/mark3labs` is a thin adapter between the [Authplane core SDK](../../core/docs/user-guide.md) and [`github.com/mark3labs/mcp-go`](https://github.com/mark3labs/mcp-go). It validates OAuth 2.1 JWT access tokens on MCP server requests, serves RFC 9728 Protected Resource Metadata, and bridges RFC 8693 token-exchange consent errors to the MCP URL elicitation shape (JSON-RPC `-32042`).

This guide is the thorough reference. The [README](../README.md) holds the hero snippet.

## 1. Install

```bash
go get github.com/authplane/go-sdk/mark3labs
```

Requires Go 1.26+. Also pulls in `github.com/authplane/go-sdk/core` and `github.com/mark3labs/mcp-go`.

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
        server.WithSessionIdManagerResolver(adapter.SessionManager()),
    )

    http.Handle(adapter.WellKnownPRMPath(), adapter.PRMHandler())
    http.Handle("/mcp", adapter.AuthMiddleware(streamable))

    http.ListenAndServe(":8080", nil)
}
```

## 3. Core concepts

`NewAdapter` constructs and owns an `*authplane.Client` and a `*resource.Resource`:

1. `authplane.NewClient` performs RFC 8414 AS metadata discovery.
2. `client.Resource(uri, resource.WithScopes(...))` builds the resource (the JWKS cache is warmed and background refresh starts).
3. If `ClientOptions` includes `WithClientCredentials` or `WithClientAuthentication`, RFC 7662 introspection is auto-wired as the revocation checker, and `TokenExchange` becomes operational. The credentials must belong to a confidential client that is the issuing client or a runtime-client of the Resource — see §8.

Internally `*Adapter` wraps [`*authplanehttp.Adapter`](../../http/docs/user-guide.md) — the generic Authplane net/http adapter — so the Bearer/DPoP middleware, scope-enforcing middleware, context helpers, and RFC 6750 / RFC 9728 `WWW-Authenticate` response (including `resource_metadata="..."` advertisement) all come from one shared implementation rather than being re-implemented per adapter. mark3labs-only additions are the context bridge and the URL-elicitation mapping.

The adapter integrates with mark3labs/mcp-go through **two coordinated hooks**:

| Hook | Purpose |
|---|---|
| `adapter.AuthMiddleware(next)` | Standard `http.Handler` middleware (delegates to `authplanehttp.Middleware()`). Parses `Authorization: Bearer …` *or* `Authorization: DPoP …`, runs the verifier, and on success stores `*verifier.VerifiedClaims` plus the raw token in the **HTTP request** context. On failure it writes a 401 with an RFC 6750 §3.1 compliant `WWW-Authenticate` header that advertises the PRM URL via `resource_metadata=` (RFC 9728 §5.1) and, when the resource is configured with scopes, the configured set via `scope=` (RFC 6750 §3). The PRM well-known path is auto-excluded from authentication. |
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
    server.WithSessionIdManagerResolver(adapter.SessionManager()),
)

http.Handle(adapter.WellKnownPRMPath(), adapter.PRMHandler())
http.Handle("/mcp", adapter.AuthMiddleware(streamable))
```

PRM is always served unauthenticated. `AuthMiddleware` wraps the streamable HTTP server.

> **Don't use `server.WithProtectedResourceMetadata(...)`** for this adapter. That option only takes effect when the streamable server owns the top-level mux (i.e. when you call `streamable.Start()`); with a custom router, PRM never gets registered. `adapter.PRMHandler()` wraps mark3labs/mcp-go's `server.NewProtectedResourceMetadataHandler` and is mounted on your outer router so it stays reachable independently of the auth-wrapped MCP endpoint.

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
| `Scopes` | `[]string` | no | Scopes advertised in the PRM document. |
| `Logger` | `*slog.Logger` | no | Receives this adapter's logs. Nil means `slog.Default()`. |
| `DevMode` | `bool` | no | Relaxes SSRF to allow HTTP, localhost, private networks. |
| `ClientOptions` | `[]authplane.Option` | no | SDK-level options: `WithClientCredentials`, `WithClientAuthentication`, `WithJWKSCacheTTL`, `WithCircuitBreaker`, `WithDPoP`, etc. |
| `VerifierOptions` | `[]verifier.Option` | no | Verifier-level options: `WithAlgorithms`, `WithClockSkew`, `WithRevocationChecker`, `WithFailClosed`. |
| `ResourceMetadataURL` | `string` | no | Overrides the URL advertised in `resource_metadata`. Empty advertises the document this adapter serves. See §5.1. |

`VerifierOptions` adds to the options set by `client.Resource`, so unrelated options keep auto-wired introspection. To turn it off, pass `verifier.WithRevocationChecker(verifier.NullRevocationChecker)`.

### 5.1 Where the PRM document lives

RFC 9728 admits two topologies, and the adapter serves both.

**(a) Resource-hosted — the default.** The SDK derives `/.well-known/oauth-protected-resource[/path]` from `Options.Resource`, `PRMHandler()` serves the document, and the 401 challenge advertises that URL. Nothing to configure.

**(b) AS-hosted.** authserver 0.2.0 and later publishes a document for every registered Resource at `<issuer>/.well-known/oauth-protected-resource/{ref}`, where `{ref}` is the RFC 9728 §3.1 path suffix of the Resource URI (or its slug). Point the challenge there when the resource server cannot host well-known paths — a platform that owns `/.well-known`, a proxy that will not forward it:

```go
adapter, err := authplanemark3labs.NewAdapter(ctx, authplanemark3labs.Options{
    Issuer:              "https://auth.example.com",
    Resource:            "https://mcp.example.com/mcp",
    Scopes:              []string{"tools/query"},
    ResourceMetadataURL: "https://auth.example.com/.well-known/oauth-protected-resource/mcp",
})
```

Only the advertisement moves. `WellKnownPRMPath()` and `PRMHandler()` keep serving the derived route, so you can switch the pointer first and retire the local endpoint afterwards. The URL is validated at construction: absolute, `https` or `http`, no fragment, no userinfo.

Whichever topology you use, RFC 9728 §3.3 pins the same constraint: the `resource` member inside the document must equal the URL clients call, byte for byte — a client must discard a document whose `resource` differs from the identifier it derived the request from. So the Resource URI registered at the authorization server, the identifier you configure here, and the public URL your server is reached on must be one and the same string, trailing slash and port included.

## 6. Main API reference

### `NewAdapter(ctx context.Context, options Options) (*Adapter, error)`

Constructs an adapter. Performs AS metadata discovery and warms the JWKS cache using `ctx`. Background refresh goroutines use their own context; `ctx` is only for startup.

### `NewAdapterFromClientAndResource(client *authplane.Client, res *resource.Resource, session SessionOptions) (*Adapter, error)`

Constructs an adapter from an already-built client and resource. Use this when sharing a single client across multiple adapters or when you need full control over construction. Returns an error if `client` is nil.

> **Lifecycle note.** `adapter.Close()` closes the client only for an adapter built with `NewAdapter`. For one built with `NewAdapterFromClientAndResource` it does nothing, and you close the client yourself.

### `(a *Adapter) AuthMiddleware(handler http.Handler) http.Handler`

Wraps an HTTP handler with Bearer (and DPoP) token authentication and the session binding described under Sessions and step-up. Equivalent to `a.Middleware()(handler)`; the call shape is preserved for fluency in mark3labs code.

- Rejects unauthenticated requests with 401 and a `WWW-Authenticate: Bearer resource_metadata="…", scope="…"` header — the PRM URL per RFC 9728 §5.1, and the resource's configured scopes (`Options.Scopes`) per RFC 6750 §3 and the MCP authorization spec's SHOULD. The `scope` param is omitted when `Options.Scopes` is empty.
- Rejects invalid Bearer tokens with 401 + `error="invalid_token"`; a bad, replayed or wrong-key DPoP proof returns the `DPoP` scheme with `invalid_dpop_proof`, as RFC 9449 requires. An outage returns 503 with no `error` in the challenge and `Retry-After`: keep the token and retry.
- On success, injects `*verifier.VerifiedClaims` and the raw token into the request context.
- The PRM well-known path is auto-excluded so the metadata endpoint stays publicly reachable even when this middleware wraps a broad route prefix.

Scopes are not checked at this layer; tools enforce their own scope (see §4.3).

### Inherited from `*authplanehttp.Adapter`

Because `*Adapter` wraps `*authplanehttp.Adapter`, the following methods from the http adapter are available directly:

- `Middleware() func(http.Handler) http.Handler` — the underlying middleware (`AuthMiddleware` is a one-line wrapper).
- `WellKnownPRMPath() string` — the RFC 9728 well-known path. Derivation strips any terminating slash after the host component (§3.1) and preserves percent-encoded octets in the path; the resource identifier itself is unchanged.
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

### `(a *Adapter) PRMHandler() http.Handler`

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

Stops background refresh goroutines of a client this adapter owns. Safe to call more than once.

### `ClaimsFromContext(ctx context.Context) *verifier.VerifiedClaims`

Returns the verified claims forwarded by `HTTPContextFunc`. Returns `nil` outside an authenticated request.

### `TokenFromContext(ctx context.Context) string`

Returns the raw bearer token forwarded by `HTTPContextFunc`. Returns `""` outside an authenticated request.

## 7. Token exchange and URL elicitation

RFC 8693 token exchange frequently runs into an authorization-server response of `consent_required` when the user has not yet granted the requested downstream access. The MCP URL elicitation protocol (JSON-RPC error code `-32042`) lets the server ask the MCP client to open a URL out-of-band — typically a consent page — and retry the original operation once the user is done.

**Operator step for cross-client exchanges.** For each MCP server that exchanges for a downstream resource it does not act as, allowlist the exchanging client on the target Resource:

```http
PATCH /admin/resources/{id}
{"policy": {"exchange": {"allowed_client_ids": ["<exchanging-client-id>"]}}}
```

A client exchanging a token issued to itself, fronted exchanges and Broker resources need nothing.

Two exchange errors look like consent problems but are not:

- `access_denied` (HTTP 403, `authplane.ErrAccessDenied`) on a cross-client exchange means the operator has not allowlisted the exchanging client on the target Resource (`policy.exchange.allowed_client_ids` / `policy.runtime.client_ids`). Re-prompting the user will not fix it — unlike `consent_required`, which the user resolves.
- `invalid_target` (HTTP 400, `authplane.ErrInvalidTarget`, RFC 8707 §2.2) means the `resource` string does not match a granted resource exactly — byte for byte, a trailing slash counts.

Neither counts toward the circuit breaker: the AS answered, it just said no.

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

The introspecting client must be **confidential** (client ID and secret) **and** either the client the token was issued to or a runtime-client of the Resource named in the token's `aud`. authserver ≥ 0.1.2 answers `{"active": false}` to anyone else — a public (secret-less) client cannot introspect at all, and a resource server introspecting with the wrong client rejects every token as revoked. Register the resource server as a runtime-client of its Resource:

```bash
authserver admin resource runtime-client add --client-id <rs-client-id> --slug <resource-slug>
```

When introspection answers `active: false` for a token that already passed local JWT verification, the SDK logs one warning per resource pointing at this requirement. The warning is written to `slog.Default()`; install a handler with `slog.SetDefault` to route it into your own logging setup, or to silence it.

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

`AuthMiddleware` accepts both `Authorization: Bearer …` and `Authorization: DPoP …` schemes — that comes from the wrappedded `*authplanehttp.Adapter`. Inbound DPoP policy (replay store, proof age, allowed algorithms, required flag) is configured on the wrapped `*resource.Resource` via `verifier.WithInboundDPoP(...)` passed in `Options.VerifierOptions`. See the [http user guide §7](../../http/docs/user-guide.md#7-dpop-sender-constrained-tokens) for the full DPoP recipe; everything there applies here.

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

adapterA, _ := authplanemark3labs.NewAdapterFromClientAndResource(client, resA, authplanemark3labs.SessionOptions{})
adapterB, _ := authplanemark3labs.NewAdapterFromClientAndResource(client, resB, authplanemark3labs.SessionOptions{})
// adapterA.Close() and adapterB.Close() do not close the shared client: close it yourself.
```

One `*authplane.Client` can back many resources and adapters. An adapter built with `NewAdapterFromClientAndResource` does not own the client, so call `client.Close()` yourself once every adapter is finished.

## 11. Development mode

```go
adapter, err := authplanemark3labs.NewAdapter(ctx, authplanemark3labs.Options{
    Issuer:   "http://localhost:9000",
    Resource: "http://localhost:8080/mcp",
    Scopes:   []string{"tools/query"},
    DevMode:  true,
})
```

`DevMode: true` relaxes the SDK's SSRF defenses: HTTP (non-TLS) issuers, `localhost`, private networks, and link-local addresses are allowed.

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
| `ErrAccessDenied` | Cross-client exchange refused (403): the exchanging client is not allowlisted on the target Resource. Operator fix, not a consent prompt. |
| `ErrInvalidTarget` | `resource` does not match a granted resource byte for byte (RFC 8707 §2.2). |
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

`Close()` is safe to call multiple times. It closes the client only for an adapter built with `NewAdapter`. See §10.

## 14. See also

- [Core user guide](../../core/docs/user-guide.md) — client, resource, verifier, outbound DPoP, token exchange semantics, full error reference.
- [Official MCP Go SDK adapter](../../mcp/docs/user-guide.md) — same SDK, different MCP library (`modelcontextprotocol/go-sdk`). Use that one if you're already on the official SDK.
- [HTTP adapter user guide](../../http/docs/user-guide.md) — parallel middleware for plain HTTP resource servers, including DPoP inbound verification.
- [`demo/`](../demo/) — runnable Calculator Service with introspection-backed revocation and per-tool scope enforcement.

## Sessions and step-up

`AuthMiddleware` binds legacy sessions to the user: a session ID must be minted for the caller's OAuth client and `sub` together. Add `server.WithSessionIdManagerResolver(adapter.SessionManager())` to the streamable server. A server without it gets every session refused, with a log line naming the fix. `Options.AllowUnboundSessions` opts out. Replicas share `Options.SessionKey`, at least 32 bytes; empty means a random per-process key. Requests on protocol 2026-07-28 have no sessions. `server.SSEServer` is not supported behind this middleware.

`RequireToolScopes` goes inside `AuthMiddleware`. Pass `RefuseUnlistedTools()` to answer 403 for a tool not in the map. A legacy session binds to the OAuth client and the subject together. It answers a `tools/call` missing a required scope with 403 and an `insufficient_scope` challenge before the tool runs.

## Other authorization servers

This adapter takes the server-neutral options of `core` through `resource.WithVerifierOptions`: `WithAcceptedTokenTypes`, `WithRequiredClaims`, `WithScopeClaims`, `WithClientClaims`, `WithAccessTokenMarkers` and `WithExpectedAudience`. See [Using another authorization server](../../core/docs/user-guide.md#using-another-authorization-server).

## Known upstream issue

mcp-go v1.5.0 has an advisory with no fix yet, GO-2026-6911, on how its client follows a `Location` header. This adapter uses mcp-go's server side and does not reach that code, which `govulncheck` confirms. Do not build an mcp-go client in the same program on the strength of this adapter's check.
