# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `core/resource/verifier`: `(*VerifiedClaims).RequireScopes(scopes ...string) error` plural helper. Returns `nil` on empty input, and on failure wraps `ErrInsufficientScope` naming every missing scope plus the scopes the token does carry, so an adapter can surface it verbatim in the `WWW-Authenticate` `error_description`.
- `core/resource/verifier`: `ErrMultipleDpopProofs` sentinel for RFC 9449 §4.3 #1 violations. `core/resource.AuthErrorResponse` maps it to a `DPoP error="invalid_dpop_proof"` 401 challenge per RFC 9449 §7.1.
- `core/resource/verifier`: `NewDPoPContext(method, url, dpopHeaderValues []string) (*DPoPContext, error)` factory — the canonical §4.3 #1 enforcement boundary. Filters blanks, splits on `,` defensively for proxies that pre-join duplicate headers, and returns `ErrMultipleDpopProofs` on more than one non-blank value.
- `core/resource/verifier`: `(*DPoPContext).Proof()` nil-safe accessor returning the single proof (or `""` when none).
- `mark3labs` module: adapter for [`mark3labs/mcp-go`](https://github.com/mark3labs/mcp-go). Wraps `*authplanehttp.Adapter` so consumers get bearer + DPoP auth, RFC 9728 PRM, and `HTTPContextFunc` integration for the mark3labs HTTP server. `HTTPContextFunc` takes `WithForwardedContextKeys(keys ...any)` and `WithContextForwarding(fn)` options to propagate values (request IDs, tracing spans, …) from the upstream request context onto the per-tool-call MCP context. See `mark3labs/docs/user-guide.md`.
- `core/resource`: `Resource.PRMURL()` returns the precomputed absolute Protected Resource Metadata URL as a single infallible source of truth.
- `core/resource`: `Resource.PRMConfig()` returns the Protected Resource Metadata as a typed `PRMConfig` struct, for feeding into third-party PRM-serving handlers (e.g. mark3labs/mcp-go's `NewProtectedResourceMetadataHandler`) without going through the dynamic `PRMResponse` map.

### Fixed
- `core/resource/verifier`: `validateHTU` compares `EscapedPath()` instead of `Path`, so an encoded `%2F` is no longer treated as equivalent to a literal `/`. The previous comparison conflated distinct request targets, weakening the RFC 9449 §4.3 `htu` binding (RFC 3986 §6.2.2.2 only permits decoding *unreserved* characters when comparing URLs).
- `core/resource/verifier`: `validateHTU` strips an explicit default port (`:80` for http, `:443` for https) on both sides before comparing (RFC 9110 §7.2), so a resource configured as `http://api.example.com:80/mcp` no longer mismatches every client that signs the port-less form.
- `core/resource/verifier`: `validateHTU` collapses an empty path to `/` on both sides before comparing, so a client signing a bare-origin htu (e.g. `https://host`) no longer fails against a server where every inbound `r.URL.EscapedPath()` is at least `/`.

### Changed
- **BREAKING (pre-1.0)** `http`: DPoP `htu` reconstruction in the `net/http` adapter no longer reads the inbound `Host` header, `r.TLS`, or `r.URL.RawQuery`. Both `Host` and `r.TLS` are proxy-controlled and would otherwise let a misconfigured edge — or an attacker forging `Host` — shift the `htu` binding to a different origin or downgrade `https` to `http` behind a TLS-terminating proxy. The adapter now sources scheme + authority from the operator-configured resource URI and contributes only the request path in raw `EscapedPath` form (query and fragment are dropped per RFC 9449 §4.3 #5). **Migration:** mount the middleware **before** any `http.StripPrefix` so `r.URL.EscapedPath()` still reflects the path the client signed; apps relying on `Host`-derived htu (or `r.TLS`-derived scheme) will see proof rejections until the resource URI is corrected to match the canonical origin.
- `core/resource/verifier`: `(*VerifiedClaims).RequireScope` delegates to `RequireScopes`, so the singular helper also emits the enriched `required scope "X"; token has scopes: …` `error_description`. Behaviour (`errors.Is(err, ErrInsufficientScope)`, 403 status, `scope="…"` parameter) is unchanged; only the error string is enriched.
- **BREAKING** `core/resource/verifier`: `DPoPContext` no longer exposes the raw proof through a public field — the previous `DPoPContext.Proof string` is replaced with an unexported slice plus the `(*DPoPContext).Proof()` accessor and the `NewDPoPContext` constructor. Route through the factory so RFC 9449 §4.3 #1 enforcement stays single-source and invalid (multi-proof) states stay unconstructable.
- `http`: HTTP adapter middleware reads `r.Header.Values("DPoP")` and routes the slice through `NewDPoPContext`. A request carrying more than one `DPoP` header returns HTTP 401 + `WWW-Authenticate: DPoP error="invalid_dpop_proof"` (RFC 9449 §4.3 #1, §7.1); the previous `r.Header.Get("DPoP")` silently picked only the first copy.
- `http`: `WWW-Authenticate` now uses a space (not a comma) before `resource_metadata` when no prior auth-param is present, matching RFC 7235 §2.1 (`Bearer resource_metadata="…"` instead of `Bearer, resource_metadata="…"`).
- `mcp.NewAdapterFromClientAndResource` now returns `(*Adapter, error)` and rejects a nil client with a typed error instead of panicking, matching the shape of its discovery-driven `NewAdapter` sibling.

## [0.1.1] - 2026-05-22

### Fixed

- DPoP `htu` validation against Authorization Servers on non-default ports. The
  SSRF-safe pinned HTTP client now keeps a non-default port in the `Host` header,
  and DPoP proof generation normalizes the `htu` claim to match: an explicit
  default port (`:80`/`:443`) is dropped, non-default ports are preserved, IPv6
  literals stay bracketed, and any userinfo is stripped from `htu`
  (RFC 9110 §7.2, RFC 9449 §4.3).

## [0.1.0] - 2026-05-17

- Initial release.
