# Authplane Go SDK User Guide

This guide documents the `Authplane Go SDK` API for MCP servers and other resource servers that need to validate JWT access tokens, perform token operations against an authorization server, and support DPoP-bound flows.

The SDK is built around these RFCs:

- RFC 8414: Authorization Server Metadata
- RFC 9068: JWT Profile for OAuth 2.0 Access Tokens
- RFC 7662: Token Introspection
- RFC 8693: Token Exchange
- RFC 7009: Token Revocation
- RFC 9449: DPoP
- RFC 9728: Protected Resource Metadata

## 1. Getting Started

### Requirements

- Go 1.24+

### Installation

```bash
go get github.com/authplane/go-sdk/core
```

### Minimal Example

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
    defer client.Close()

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

## 2. Creating the Client

`authplane.NewClient` is the top-level entry point. It owns AS metadata discovery, JWKS caching, token caching, DPoP configuration, and the circuit breaker.

```go
import "github.com/authplane/go-sdk/core/authplane"

km, err := authplane.NewDPoPKeyMaterial(jose.ES256)
// For production: load key material from a secrets manager or vault
// instead of generating ephemeral keys.

client, err := authplane.NewClient(ctx, "https://auth.example.com",
    authplane.WithClientCredentials("my-client", "s3cret"),
    authplane.WithDPoP(km),
    authplane.WithJWKSCacheTTL(5 * time.Minute),
    authplane.WithCircuitBreaker(5, 30 * time.Second),
    authplane.WithTokenCacheTTLBuffer(30 * time.Second),
)
```

### Client options

| Option | Default | Description |
|--------|---------|-------------|
| `WithClientCredentials(id, secret)` | none | OAuth 2.0 client credentials for token operations |
| `WithDPoP(km)` | disabled | Enable outbound DPoP proof generation with provided key material |
| `WithFetchSettings(s)` | production | Override SSRF / HTTP transport settings — see [Section 10](#10-fetch-settings-and-ssrf-protection) |
| `WithJWKSCacheTTL(d)` | `5m` | Default JWKS cache TTL |
| `WithCircuitBreaker(threshold, cooldown)` | `5, 30s` | Circuit breaker failure threshold and cooldown |
| `WithTokenCacheTTLBuffer(d)` | `30s` | Evict cached tokens this long before expiry |

For local development, set the `AUTHPLANE_DEV_MODE` environment variable (no code change needed):

```bash
export AUTHPLANE_DEV_MODE=1
```

This is equivalent to passing `WithFetchSettings(DevModeFetchSettings())` and is useful in CI or scripts. An explicit `WithFetchSettings` always wins over the env var.

### What happens during creation

1. Metadata is fetched from the RFC 8414 discovery URL derived from the issuer.
   For issuers with a path component, the SDK inserts `/.well-known/oauth-authorization-server` before the issuer path as required by RFC 8414.
2. The metadata document must contain an `issuer` that exactly matches the configured issuer.
3. Required discovered endpoints (token, introspection, revocation) are resolved from metadata only. The SDK does not synthesize fallback endpoints.
4. The discovered `jwks_uri` is fetched and cached.
5. Background refresh goroutines are started for metadata and JWKS.
6. If client credentials are provided, an internal OAuth client is created with the discovered endpoints.
7. If DPoP is configured, a `DPoPSigner` is created from the provided key material.

If initial metadata or JWKS fetch fails, `NewClient` returns an error.

### Cleanup

Always call `Close()` when the client is no longer needed to stop background goroutines:

```go
client, err := authplane.NewClient(ctx, issuer, opts...)
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

## 3. Verifying Access Tokens

### Creating a Resource

Create a `Resource` from the client. The resource wraps a `TokenVerifier` and provides PRM generation.

```go
import (
    "github.com/authplane/go-sdk/core/resource"
    "github.com/authplane/go-sdk/core/resource/verifier"
    "github.com/go-jose/go-jose/v4"
)

res, err := client.Resource("https://api.example.com",
    resource.WithScopes("read", "write"),
    resource.WithVerifierOptions(
        verifier.WithAlgorithms(jose.RS256, jose.ES256),
        verifier.WithClockSkew(30 * time.Second),
        verifier.WithRevocationChecker(myChecker),
        verifier.WithFailClosed(),
    ),
)
```

### Verifier options

| Option | Default | Description |
|--------|---------|-------------|
| `WithAlgorithms(algs...)` | `ES256, RS256` | Allowed JWT signature algorithms. HMAC and `none` are rejected. |
| `WithClockSkew(d)` | `30s` | Tolerance for `exp`/`iat` clock drift. |
| `WithRevocationChecker(fn)` | disabled | Custom revocation callback. |
| `WithFailClosed()` | fail-open | Reject tokens when revocation check errors (instead of accepting). |

### Verifier rules

- Only `RS256` and `ES256` are accepted by default.
- HMAC algorithms and `none` are rejected at construction time.
- The JWT header `typ` must be `at+jwt`.
- The JWT `iss` must match the configured issuer.
- The JWT `aud` must contain the resource URI.
- Required claims: `sub`, `client_id`, `exp`, `iat`, `jti`.
- Algorithm is checked in the JWT header before any cryptographic operation.
- JWK selection is by `kid` and `alg`.

### Bearer verification

```go
claims, err := res.VerifyToken(ctx, token)
if err != nil {
    status := resource.HTTPStatus(err)
    // ...
}
```

### DPoP-bound verification

DPoP support is opt-in per resource. Configure it once on the `Resource`
with `verifier.WithInboundDPoP`, then pass a per-request `DPoPContext`
into each `VerifyToken` call:

```go
res, err := client.Resource("https://api.example.com",
    resource.WithVerifierOptions(verifier.WithInboundDPoP(verifier.InboundDPoPOptions{
        ReplayStore: verifier.NewInMemoryDPoPReplayStore(),
        MaxProofAge: 5 * time.Minute,
        ClockSkew:   30 * time.Second,
        Required:    true, // optional: rejects bearer-only tokens
    })),
)

claims, err := res.VerifyToken(ctx, token, resource.WithDPoP(&verifier.DPoPContext{
    Method: "POST",
    URL:    "https://api.example.com/tools/invoke",
    Proof:  dpopHeader,
}))
```

`InboundDPoPOptions` controls all inbound DPoP policy in one place:

| Field | Default | Effect |
|---|---|---|
| `ReplayStore` | `nil` | When non-nil, enforces JTI uniqueness within the proof lifetime window. |
| `MaxProofAge` | `300s` (`DefaultDPoPProofLifetime`) | Maximum age of a proof, measured from its `iat`. |
| `ClockSkew` | `30s` (`DefaultDPoPClockSkew`) | Tolerance for proof `iat` being in the future. Capped at `MaxClockSkew` (5 min). |
| `AllowedProofAlgorithms` | `ES256, RS256, PS256` | JWS algorithms accepted for proofs. Dangerous algorithms (`none`, HMAC) are always rejected. |
| `Required` | `false` | When `true`, bearer-only tokens are rejected with `ErrDPoPRequired` and PRM advertises `dpop_bound_access_tokens_required: true`. |

The resource has three implicit policy modes:

| Mode | Trigger | Behavior |
|---|---|---|
| **Not supported** | `WithInboundDPoP` not called | Bearer accepted; DPoP-bound token → `verifier.ErrDPoPNotSupported`. |
| **Supported** | `WithInboundDPoP(…)` with `Required: false` | Bearer accepted; DPoP-bound token validated against the bundle. |
| **Required** | `WithInboundDPoP(…)` with `Required: true` | Bearer rejected with `verifier.ErrDPoPRequired`; DPoP-bound token validated. |

When the token has a `cnf.jkt` binding, the verifier checks:

- The DPoP proof is present and valid
- Proof `typ` is `dpop+jwt`
- Proof algorithm is in `AllowedProofAlgorithms`
- Proof `htm`, `htu`, `iat`, and `jti` are valid; `iat` is within `now − MaxProofAge − ClockSkew` to `now + ClockSkew`
- `ath` matches the SHA-256 hash of the access token
- Replay detection runs through the supplied `ReplayStore` (when non-nil)
- The proof key thumbprint matches the token's `cnf.jkt`

## 4. Working with VerifiedClaims

`VerifiedClaims` holds the validated claims from a JWT access token. All fields are unexported; use accessor methods to read values. Returned slices and maps are copies to prevent mutation.

### Accessors

```go
claims.Sub()        // string   - subject (user ID)
claims.ClientID()   // string   - OAuth client_id
claims.Issuer()     // string   - token issuer
claims.JTI()        // string   - JWT ID
claims.KID()        // string   - signing key ID
claims.AgentID()    // string   - agent_id claim (Authplane extension)
claims.Scopes()     // []string - copy of parsed scopes
claims.Audience()   // []string - copy of token audiences
claims.ExpiresAt()  // int64    - Unix epoch
claims.IssuedAt()   // int64    - Unix epoch
claims.NotBefore()  // int64    - Unix epoch (0 when nbf is absent)
claims.Raw()        // map[string]any - all claims (deep copy)
```

### Scope helpers

```go
claims.HasScope("tools/echo")          // bool
claims.RequireScope("tools/echo")      // error (ErrInsufficientScope if missing)
```

### Custom claims

```go
claims.HasClaim("email")                   // bool (checks key exists)
claims.HasClaimValue("email_verified", true) // bool (checks key + value)
claims.Claim("email")                       // any or nil
```

### Delegation claims (RFC 8693)

```go
claims.Act()          // map[string]any for "act" claim (delegation chain)
claims.MayAct()       // map[string]any for "may_act" claim (authorized actors)
claims.AgentChain()   // []string for "agent_chain" claim (Authplane extension)
```

### DPoP confirmation

```go
claims.IsDPoPBound()      // bool
claims.DPoPThumbprint()   // JWK thumbprint string from cnf.jkt
claims.Cnf()              // raw cnf map (deep copy)
claims.DPoPProof()        // *VerifiedDPoPProof or nil
```

`DPoPProof()` returns the validated DPoP proof attached to a sender-constrained
token. It is nil for bearer tokens or when no DPoP context was supplied to
`VerifyToken`.

```go
if proof := claims.DPoPProof(); proof != nil {
    log.Printf("dpop audit: jti=%s htm=%s htu=%s iat=%d jkt=%s",
        proof.JTI, proof.HTM, proof.HTU, proof.IAT, proof.KeyThumbprint)
}
```

Fields: `JTI`, `HTM`, `HTU`, `IAT`, `KeyThumbprint`, `Nonce`. Use these for
audit logging, replay-suspect investigation, or proof-age forensics — the
verifier never re-parses or mutates the proof after publication.

## 5. Revocation Checking

By default, verification only uses the JWT and JWKS. Revocation checking adds a post-validation step.

### Built-in introspection-based revocation

Use the facade's `Introspect` method as a revocation checker:

```go
res, err := client.Resource("https://api.example.com",
    resource.WithVerifierOptions(
        verifier.WithRevocationChecker(func(ctx context.Context, claims *verifier.VerifiedClaims, rawToken string) (bool, error) {
            resp, err := client.Introspect(ctx, rawToken)
            if err != nil {
                return false, err // fail-open by default
            }
            return !resp.Active, nil
        }),
    ),
)
```

### Custom revocation checker

Back revocation with Redis, a local blocklist, or any store:

```go
verifier.WithRevocationChecker(func(ctx context.Context, claims *verifier.VerifiedClaims, rawToken string) (bool, error) {
    revoked, err := redis.SIsMember(ctx, "revoked_jtis", claims.JTI()).Result()
    if err != nil {
        return false, err // fail-open: error means "don't know"
    }
    return revoked, nil // true = revoked
})
```

### Fail-open behavior

By default, if the revocation checker returns an error, the token is accepted (fail-open). This prevents a down revocation store from blocking all requests.

To reject tokens when the revocation check fails, use `WithFailClosed()`:

```go
resource.WithVerifierOptions(
    verifier.WithRevocationChecker(myChecker),
    verifier.WithFailClosed(),
)
```

To explicitly disable revocation checking (e.g. to override a default introspection checker), use `NullRevocationChecker`:

```go
resource.WithVerifierOptions(
    verifier.WithRevocationChecker(verifier.NullRevocationChecker),
)
```

## 6. Token Operations

All AS-facing operations use the current discovered metadata endpoints and the configured circuit breaker. Client credentials must be configured via `WithClientCredentials`.

### ClientCredentials

```go
resp, err := client.ClientCredentials(ctx,
    []string{"read", "write"},
    []string{"https://api.example.com"},
)
fmt.Println(resp.AccessToken)
fmt.Println(resp.TokenType)
fmt.Println(resp.ExpiresIn)
```

Successful responses are cached in memory by the normalized `(scopes, resources)` combination. Cached entries are evicted before expiry based on `WithTokenCacheTTLBuffer`.

### Introspect

```go
resp, err := client.Introspect(ctx, accessToken)
fmt.Println(resp.Active, resp.Subject, resp.Scope)
```

### Revoke

```go
err := client.Revoke(ctx, accessToken)
```

Per RFC 7009, any 2xx response is treated as success.

### TokenExchange

```go
resp, err := client.TokenExchange(ctx, authplane.TokenExchangeInput{
    SubjectToken: userToken,
    ActorToken:   agentToken,       // optional: delegation
    Scopes:       []string{"calendar.read"},  // optional: scope narrowing
    Resources:    []string{"https://downstream.example.com/"}, // optional: audience binding (RFC 8707)
    Audiences:    []string{"downstream"},     // optional
})
```

`TokenExchangeInput` fields:

| Field | Required | Description |
|-------|----------|-------------|
| `SubjectToken` | yes | Token to exchange |
| `SubjectTokenType` | no | Defaults to access token URN |
| `ActorToken` | no | Actor token for delegation |
| `ActorTokenType` | no | Defaults to access token URN |
| `Scopes` | no | Requested scopes (must be a subset of the subject token's scope) |
| `Resources` | no | Target audience URIs (RFC 8707), multiple values supported |
| `Audiences` | no | Target audience strings, multiple values supported |

## 7. Handling Consent-Required Errors

When a token exchange fails because the user has not yet consented to a third-party service, the AS returns `consent_required` or `interaction_required`. The SDK wraps these into a `*ConsentRequiredError` with the consent URL and description from the AS response.

```go
resp, err := client.TokenExchange(ctx, authplane.TokenExchangeInput{
    SubjectToken: userToken,
    Scopes:       []string{"calendar.read"},
    Resources:    []string{"https://calendar.example.com/"},
})

var consentErr *authplane.ConsentRequiredError
if errors.As(err, &consentErr) {
    // consentErr.ConsentURL  — URL the user should visit to grant consent
    // consentErr.Description — human-readable explanation from the AS
    // consentErr.Cause       — underlying sentinel (ErrConsentRequired or ErrInteractionRequired)
    log.Printf("consent needed: %s — visit %s", consentErr.Description, consentErr.ConsentURL)
}
```

`ConsentRequiredError` implements `Unwrap()`, so `errors.Is` works through wrapping chains:

```go
if errors.Is(err, authplane.ErrConsentRequired) {
    // consent_required — use errors.As to access the full error details
}
```

The `ConsentURL` field may be empty if the AS does not yet include it in its error response. The `Description` field comes from the AS `error_description`.

MCP adapters can use this error to return a `URLElicitationRequiredError` (MCP spec SEP-1036, JSON-RPC code `-32042`) to prompt the user to complete an out-of-band consent flow.

## 8. DPoP for Outbound Calls

Use `DPoPSigner` when your MCP server needs sender-constrained tokens or when the AS/downstream service requires DPoP proofs.

### Creating a signer

The facade creates a `DPoPSigner` automatically when `WithDPoP` is configured:

```go
km, err := authplane.NewDPoPKeyMaterial(jose.ES256)
// handle err

client, err := authplane.NewClient(ctx, issuer,
    authplane.WithClientCredentials("my-client", "s3cret"),
    authplane.WithDPoP(km),
)
```

You can also create one directly:

```go
// Generate a new key pair
signer, err := authplane.NewDPoPSigner(jose.ES256)

// Or use an existing key
signer, err := authplane.NewDPoPSignerWithKey(existingKey, jose.ES256)
```

### Generating proofs

```go
proof, err := signer.GenerateProof("POST", "https://auth.example.com/oauth/token", &authplane.DPoPProofOptions{
    Nonce:       "server-nonce",     // optional: from DPoP-Nonce header
    AccessToken: "eyJhbGci...",      // optional: for ath binding
})
```

### Thumbprint

```go
jkt := signer.Thumbprint() // base64url SHA-256 of the public key
```

### Accessing the signer from the facade

```go
if signer := client.DPoPSigner(); signer != nil {
    proof, err := signer.GenerateProof("GET", targetURL, nil)
}
```

## 9. Inbound DPoP Summary

The single `VerifyToken()` entrypoint handles both bearer and DPoP-bound tokens. Pass a `DPoPContext` to enable sender-constraint validation:

- It validates the access token first.
- If `cnf.jkt` is present, the proof must be supplied and valid.
- It validates proof signature, `typ`, `htm`, normalized `htu`, `iat`, `ath`, and replay state.
- It enforces proof-to-token binding by comparing the proof's JWK thumbprint to `cnf.jkt`.
- Proof lifetime is enforced at 300 seconds by default (`DefaultDPoPProofLifetime`).

If the token has no `cnf.jkt`, verification succeeds as a normal bearer token even when DPoP context is provided.

Outbound DPoP and inbound DPoP use different state:

- Outbound proofs are generated by `authplane.DPoPSigner`.
- Inbound replay detection is supplied through `verifier.DPoPReplayStore`.

### DPoPReplayStore interface

```go
type DPoPReplayStore interface {
    CheckAndStore(jti string, expiresAt time.Time) (stored bool, err error)
}
```

Returns `stored=true` when the JTI was stored (first use), or `stored=false` when it was already present (replay detected). If `CheckAndStore` returns an error, the proof is rejected.

The SDK provides `InMemoryDPoPReplayStore` for single-process deployments. For distributed systems, implement `DPoPReplayStore` with Redis or a shared database.

## 10. Fetch Settings and SSRF Protection

Metadata discovery, JWKS fetches, and all OAuth form posts use a `FetchSettings` value that controls SSRF protection, HTTP/HTTPS, network allowlists, and timeout. The defaults are production-safe; `WithFetchSettings` lets you override them.

### Production defaults (`DefaultFetchSettings`)

- SSRF protection enabled
- HTTPS only
- No localhost
- No private networks
- 10-second timeout
- DNS pinning
- No redirects

### Tuning fetch settings

```go
import "time"

settings := authplane.DefaultFetchSettings()
settings.Timeout = 30 * time.Second

client, err := authplane.NewClient(ctx, issuer,
    authplane.WithFetchSettings(settings),
)
```

`FetchSettings` fields:

| Field | Default | Description |
|-------|---------|-------------|
| `SSRFProtection` | `true` | When `false`, requests bypass DNS pinning and IP validation. |
| `AllowHTTP` | `false` | Permit `http://` URLs (HTTPS-only when `false`). |
| `AllowLocalhost` | `false` | Permit `127.0.0.0/8` / `::1`. |
| `AllowPrivateNets` | `false` | Permit `10/8`, `172.16/12`, `192.168/16`, `100.64/10`. |
| `Timeout` | `10s` | Per-request HTTP timeout. |

Cloud-metadata addresses (`169.254.169.254`, link-local, multicast) are always blocked when `SSRFProtection` is enabled regardless of the other flags.

### Development mode

For local development against an authorization server on `localhost`:

```go
client, err := authplane.NewClient(ctx, "http://localhost:9000",
    authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
)
```

`DevModeFetchSettings()` allows HTTP, localhost, and private-network endpoints while keeping SSRF protection enabled for cloud-metadata addresses. It is intended for local development only.

Setting `AUTHPLANE_DEV_MODE=1` in the environment achieves the same effect without code changes (useful in CI). Explicit `WithFetchSettings` always overrides the env var.

### Settings precedence

1. Explicit `WithFetchSettings(...)` — highest priority.
2. `AUTHPLANE_DEV_MODE=1` env var → `DevModeFetchSettings()`.
3. `DefaultFetchSettings()` — production-safe defaults.

## 11. Error Handling

All SDK errors are sentinel values testable with `errors.Is`.

### Verification errors (`resource/verifier`)

```go
import "github.com/authplane/go-sdk/core/resource/verifier"

claims, err := res.VerifyToken(ctx, token)
if err != nil {
    if errors.Is(err, verifier.ErrInsufficientScope) {
        // 403 Forbidden
    } else if errors.Is(err, verifier.ErrTokenExpired) {
        // 401 Unauthorized
    }
    // ...
}
```

Convenience helper in the `resource` package:

```go
import "github.com/authplane/go-sdk/core/resource"

status := resource.HTTPStatus(err)
// 403 for ErrInsufficientScope
// 503 for ErrJWKSUnavailable, ErrMetadataUnavailable
// 401 for all other verifier errors
// 500 for ErrSSRFBlocked, ErrProtocolError, and unknown errors
```

For generating `WWW-Authenticate` headers:

```go
status, headers, body := resource.AuthErrorResponse(err)
```

### OAuth errors (`authplane`)

```go
resp, err := client.ClientCredentials(ctx, scope, resource)
if err != nil {
    if errors.Is(err, authplane.ErrInvalidGrant) {
        // subject token invalid
    } else if errors.Is(err, authplane.ErrCircuitOpen) {
        // AS unavailable, circuit breaker tripped
    }
}
```

For consent-required errors from token exchange, use `errors.As` to access the typed error (see [Section 7](#7-handling-consent-required-errors)).

## 12. Protected Resource Metadata (RFC 9728)

Generate an RFC 9728 protected resource metadata document:

```go
prm := res.PRMResponse()    // map[string]any
prmJSON := res.PRMJSON()    // []byte (pre-serialized JSON)
```

Example output:

```json
{
  "resource": "https://api.example.com",
  "authorization_servers": ["https://auth.example.com"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["read", "write"],
  "dpop_signing_alg_values_supported": ["ES256", "RS256", "PS256"]
}
```

`scopes_supported` is emitted only when the resource was created with `resource.WithScopes(...)`. `dpop_signing_alg_values_supported` is always included and reports the proof-signature algorithms the verifier accepts for inbound DPoP proofs (RFC 9728 §2).

Serve it at `/.well-known/oauth-protected-resource` in your framework of choice. The SDK does not include HTTP middleware -- integration with `net/http`, gRPC, or other frameworks is left to adapter packages or application code.

## 13. Advanced Notes

### Circuit breaker behavior

The circuit breaker protects AS-bound operations from cascading failure. It classifies errors to avoid tripping on business-logic responses where the AS is healthy.

**Errors that trip the breaker** (infrastructure failures + permanent misconfiguration):
- Server-side failures (`server_error`, HTTP 5xx)
- Transport failures (connection refused, DNS, timeout)
- Permanent client misconfiguration (`invalid_client`, `unauthorized_client`)
- Metadata/JWKS discovery failures

**Errors that do NOT trip the breaker** (AS responded correctly):
- `consent_required` / `interaction_required` — user needs to take action
- `invalid_grant` — per-token condition (expired, revoked)
- `invalid_scope` — per-request (wrong scopes requested)
- `use_dpop_nonce` — per-request (nonce retry)
- SSRF validation failures — local configuration, not AS issue

After cooldown expiry, the next call is allowed as a half-open probe. Successful probes reset the circuit to closed.

Configure via:

```go
authplane.WithCircuitBreaker(10, 60 * time.Second) // threshold=10, cooldown=60s
```

### Unknown kid

If a token references an unknown `kid`, the JWKS cache is force-refreshed once before the verifier gives up. This supports normal key rotation without turning every bad token into repeated network traffic. If the key is still unresolved after that refresh, the token is rejected as invalid rather than reported as a JWKS outage.

### Strict discovery behavior

The SDK fails closed on discovery problems:

- Metadata `issuer` mismatch is rejected.
- Missing discovered endpoints are not guessed from the issuer URL.
- The SDK does not synthesize fallback token, introspection, or revocation endpoints.

### Token caching

Client-credentials responses are cached in memory by `(scope, resource)`. Token-exchange responses are cached by the effective exchange inputs so distinct subject, actor, audience, resource, or scope combinations do not reuse the same cached token. Cached entries are evicted slightly before expiry based on `WithTokenCacheTTLBuffer` (default 30 seconds).
