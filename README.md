# Authplane Go SDK

[![CI](https://img.shields.io/github/actions/workflow/status/AuthPlane/go-sdk/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/AuthPlane/go-sdk/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/AuthPlane/go-sdk/release.yml?style=flat-square&label=release)](https://github.com/AuthPlane/go-sdk/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/authplane/go-sdk?style=flat-square)](https://goreportcard.com/report/github.com/authplane/go-sdk)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](LICENSE)

The Authplane Go SDK is a production-grade library for protecting MCP servers and OAuth 2.1 resource servers with tokens issued by an [Authplane authorization server](https://github.com/AuthPlane/authserver).

## Why Authplane

- **One call wires up everything.** `authplanemcp.NewAdapter(...)` performs RFC 8414 metadata discovery, warms the JWKS cache, validates RFC 9068 access tokens, and serves RFC 9728 Protected Resource Metadata — no configuration ceremony.
- **Secure defaults, no footguns.** Asymmetric algorithms only, strict claim validation, SSRF-hardened fetches, background JWKS refresh, and a circuit breaker around the AS — out of the box.
- **Standards-aligned.** OAuth 2.1, DPoP (RFC 9449), Token Exchange (RFC 8693), Token Introspection (RFC 7662), Protected Resource Metadata (RFC 9728).

## Quickstart — MCP server with auth

Using the [`mcp` adapter](mcp/README.md) for the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk):

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
        Issuer:   "https://auth.company.com",
        Resource: "https://mcp.company.com/mcp",
        Scopes:   []string{"tools/query"},
    })
    if err != nil {
        panic(err)
    }
    defer adapter.Close() // stops JWKS refresh goroutines, closes the client

    server := mcp.NewServer(&mcp.Implementation{Name: "My Server", Version: "1.0.0"}, nil)

    handler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server { return server }, nil)

    http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
    http.Handle("/mcp", adapter.AuthMiddleware(handler))

    http.ListenAndServe(":8080", nil)
}
```

That's a complete, secure, standards-compliant MCP resource server. For a plain HTTP resource server, see the [`http` adapter](http/README.md).

## Packages

| Package | Install | Purpose |
| --- | --- | --- |
| [`core`](core/README.md) | `go get github.com/authplane/go-sdk/core` | Framework-agnostic JWT validation, JWKS caching, DPoP, introspection, token exchange, PRM. |
| [`http`](http/README.md) | `go get github.com/authplane/go-sdk/http` | `net/http` middleware with Bearer and DPoP sender-constrained token support. |
| [`mcp`](mcp/README.md) | `go get github.com/authplane/go-sdk/mcp` | Adapter for the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk). |

Each package has its own quickstart and user guide; start at the package README that matches your integration target.

## Requirements

- Go 1.24+ (`core`, `http`) / Go 1.25+ (`mcp`, forced by `github.com/modelcontextprotocol/go-sdk`)

## Capabilities

### Standards and RFCs

- **OAuth 2.1** (draft-ietf-oauth-v2-1) — profile-aligned token validation defaults.
- **RFC 8414** — Authorization Server Metadata discovery.
- **RFC 9068** — JWT Profile for OAuth 2.0 Access Tokens (`typ: at+jwt`, required claims).
- **RFC 7662** — Token Introspection (auto-wired as a revocation checker when credentials are supplied).
- **RFC 7009** — Token Revocation.
- **RFC 8693** — Token Exchange, with `ConsentRequiredError` surfacing for MCP consent flows.
- **RFC 9728** — OAuth Protected Resource Metadata, with JSON generation and well-known path derivation.
- **RFC 9449** — DPoP, covering both outbound proof generation (with nonce handling) and inbound proof verification with replay detection.
- **RFC 8707** — Resource Indicators (honored by client-credentials and token exchange).
- **RFC 7234** — HTTP caching semantics applied to authorization-server metadata and JWKS responses (`Cache-Control: max-age` honored, `no-store` respected).
- **RFC 6750** — Bearer Token Usage; middleware emits RFC-compliant `WWW-Authenticate` responses.
- **RFC 7519 / 7517** — JWT and JWKS.

### Security

- Algorithm-confusion defenses: only asymmetric algorithms are accepted; `none`, `HS256`, `HS384`, `HS512` are always rejected at construction. Token-verifier default is `RS256`, `ES256` (RFC 9068). Inbound DPoP proof default is `ES256`, `RS256`, `PS256` (a superset, since proofs are short-lived and the algorithm set is independent from the access-token JWS choice); narrow via `InboundDPoPOptions.AllowedProofAlgorithms` if your deployment is stricter.
- Strict claim validation: exact `iss` match, `aud` membership, `typ: at+jwt`, required claims (`sub`, `client_id`, `exp`, `iat`, `jti`), configurable clock skew with a 5-minute ceiling.
- SSRF hardening on every outbound fetch: HTTPS-only, DNS pinning, private/loopback/link-local blocking, cloud metadata (169.254.0.0/16) always blocked, response size limits, no redirects. A dev-mode toggle relaxes these for `localhost` development only.
- JWKS resilience: stale-cache fallback, background refresh, force-refresh on `kid` miss.
- DPoP (inbound): `htm`/`htu`/`ath` checks, `cnf.jkt` binding enforcement, configurable replay store (default in-memory, pluggable for distributed deployments).
- DPoP (outbound): proof generation with automatic `use_dpop_nonce` retry.
- Circuit breaker around AS interactions with configurable threshold and cooldown.
- Token caching with TTL buffers for client-credentials and token-exchange responses; cache entries are evicted on revocation.

### Framework integrations

- [`net/http`](http/README.md) middleware for plain resource servers.
- [MCP Go SDK](mcp/README.md) adapter, including URL elicitation mapping for RFC 8693 consent flows.

### Observability

- `log/slog` is used throughout; structured fields are emitted for JWKS refreshes, circuit breaker transitions, and verification failures. Emit your own logger by setting the default `slog` handler in your application.

## Documentation

- Package READMEs — [`core`](core/README.md) · [`http`](http/README.md) · [`mcp`](mcp/README.md)
- Package user guides — [`core`](core/docs/user-guide.md) · [`http`](http/docs/user-guide.md) · [`mcp`](mcp/docs/user-guide.md)
- [`CHANGELOG.md`](CHANGELOG.md)
- [`SECURITY.md`](SECURITY.md) — reporting vulnerabilities
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development setup and PR guidelines
- [`RELEASE_POLICY.md`](RELEASE_POLICY.md) — versioning and release flow

## Status

| Package | Go Reference |
| --- | --- |
| `core` | [![Go Reference](https://pkg.go.dev/badge/github.com/authplane/go-sdk/core.svg)](https://pkg.go.dev/github.com/authplane/go-sdk/core) |
| `http` | [![Go Reference](https://pkg.go.dev/badge/github.com/authplane/go-sdk/http.svg)](https://pkg.go.dev/github.com/authplane/go-sdk/http) |
| `mcp`  | [![Go Reference](https://pkg.go.dev/badge/github.com/authplane/go-sdk/mcp.svg)](https://pkg.go.dev/github.com/authplane/go-sdk/mcp) |

## License

Apache 2.0 — see [LICENSE](LICENSE).
