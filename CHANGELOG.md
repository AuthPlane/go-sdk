# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-11-11

### Added
- `core/authplane`: `OAuthError` gives a server error's code, description, status and retry delay; `ErrSSRFBlocked`, `ErrDNSResolution`, `ErrNoIntrospectionEndpoint`, `ErrMetadataUnavailable`, `ErrCredentialsNotConfigured` and `ErrClientClosed` are exported.
- `core/authplane`: `FetchSettings` gains `Proxy`, `UserAgent` and `Observe`; `WithLogger`, `WithoutTokenVerification` and `NewClientAndResource` are new.
- `core/resource`: `Resource.PRMHandler`, `Resource.AuthErrorResponse`, `SanitizeChallengeValue` and `ToolScopeGuardConfig.RefuseUnlisted`; `RefuseUnlistedTools` in `mcp` and `mark3labs`.
- `core/resource/verifier/verifiertest`: `NewClaims` gives tests real claims by signing and verifying a token.
- `core/authplane`: `ClientAuthPrivateKeyJWT` authenticates with a signed assertion (RFC 7523), and `JWTBearer` performs the JWT-bearer grant, which also redeems an ID-JAG.
- `core`: RFC 9396 `authorization_details` on token requests through `TokenExchangeInput`, `JWTBearerInput` and `ClientCredentialsInput`, token responses, introspection and verified claims.
- `core/authplane`: `FetchSettings.RootCAs` trusts a private CA on every fetch.
- `core/authplane`: `Client.Metadata` returns the discovered metadata, including members with no typed field, and `WithJWKSMaxStale` limits how long cached keys are trusted in an outage.
- `core/resource/verifier`: `ErrRevocationNotSupported` lets a checker say the server cannot check, and `WithScopeImplication` lets a broader scope satisfy a narrower one (MCP authorization).
- `mcp`, `mark3labs`: `RequireToolScopes`, built on `resource.ToolScopeGuard`, answers a missing tool scope with 403 and an `insufficient_scope` challenge before the tool runs.
- `mcp`: `ReceivingMiddleware` and `ClaimsFromRequest` give each call its own request's claims.
- `mark3labs`: `SessionManager` mints session IDs bound to the caller, with `Options.AllowUnboundSessions` and `Options.SessionKey`.
- `http`: `WithPRMHandler` sets the handler `Middleware` uses for the metadata path.
- `core/resource/verifier`: `WithAcceptedTokenTypes`, `WithRequiredClaims`, `WithScopeClaims`, `WithClientClaims`, `WithAccessTokenMarkers` and `WithExpectedAudience` let the verifier accept tokens from other standard servers; the defaults are unchanged.
- `core/resource/verifier`: `TokenVerifier.VerifyDPoPBinding` and `TokenBinding` apply the resource's DPoP policy to a token validated by introspection; `Resource.VerifyDPoPBinding` takes the proof through `WithDPoP`.

### Fixed
- `core/authplane`: connections are reused per host, the next validated address is tried when a connection fails, and concurrent client credentials callers share one request.
- `core/authplane`: a cache hit returns the whole response with `ExpiresIn` counting down, `expires_in` may be a string, and `NewDPoPSignerWithKey` accepts HSM and KMS signers.
- `core/authplane`: an unsafe consent URL is dropped on every grant, not only token exchange.
- `core/authplane`: secrets and keys are redacted when formatted or logged, client secrets when marshaled to JSON, and server text in errors is cleaned and shortened.
- `mark3labs`: a session binds to client and subject together, so two clients of one user cannot use each other's sessions.
- `core/internal/ssrf`: an address with an IPv4 address inside it no longer skips the private-range check on the outer address.
- `core/internal/oauth`: only one exact `active: true` member makes an introspection answer active, so a badly typed field or a case-variant key no longer leads to an acceptance.
- `core/authplane`: `Revoke` evicts entries holding the token as access or refresh token and those exchanged from it at any depth, and a cached exchange result ends no later than its source JWT's `exp`.
- `core/resource/verifier`: `typ: application/at+jwt` is accepted, and `typ` ignores case (RFC 9068 section 4).
- `core/resource/verifier`: a JWKS key with no `alg` matches when its key type fits the token's algorithm (RFC 7517 section 4.4).
- `mcp`: application-written `WWW-Authenticate` challenges pass through unchanged.
- `core/resource/verifier`: a proof with the wrong key no longer enters the replay store, replay entries are scoped by key, and EdDSA proofs verify.
- `core/authplane`: token exchange accepts `token_type: N_A` (RFC 8693) and does not cache that result; a cache hit keeps `issued_token_type`.
- `core/authplane`: the token cache is bounded and its keys hold no tokens; different requests can no longer share a key.
- `core/internal/metadata`: discovery also tries the OpenID form with the well-known path inserted.
- `core/resource/verifier`: an unknown `kid` while the JWKS is unreachable is `ErrJWKSUnavailable`, not `ErrInvalidClaims`.
- `core`: background refresh keeps retrying after an outage. Fetches are shared and run apart from callers: a caller leaves at its own deadline, and cannot abort a fetch or reopen a refresh floor. Keys are installed once per fetch, so a removed key cannot return.
- `core`: a metadata document or JWKS that fails validation no longer replaces a good one, and a JWKS key of an unsupported type no longer discards the others.
- `core/authplane`: the circuit breaker recovers after a half-open probe that gets a policy answer, is blocked, or is cancelled; it used to stay open until restart.
- `core/authplane`: introspection has its own circuit breaker, so token endpoint failures no longer stop revocation checks.

### Removed
- **BREAKING** `core/authplane`: `AUTHPLANE_DEV_MODE`. **Migration:** pass `WithFetchSettings(DevModeFetchSettings())`.
- **BREAKING** `core/resource/verifier`: `ErrSSRFBlocked`, `ErrProtocolError`, `Algorithms` and `StringOrSlice`, which nothing returned or used, and `authplane.StringOrSlice`. **Migration:** use `authplane.ErrSSRFBlocked` and `authplane.ErrProtocolError`; there is no replacement for the others, and `Audience` fields are `[]string`.
- **BREAKING** `core/resource`: `AuthErrorResponseWithMetadata`, `AuthErrorResponseVerbose` and the realm argument of `AuthErrorResponse`. **Migration:** `AuthErrorResponse` with `WithChallengeMetadata`, `WithVerboseDescription` and `WithRealm`.
- **BREAKING** `core/resource/verifier`: `ParseClaims`, which built `VerifiedClaims` with no verification. **Migration:** in tests, use `verifiertest.NewClaims`.
- **BREAKING** `core/authplane`: `DoTokenRequestForTesting` and `NewDPoPProviderForTesting`. **Migration:** use `Client` with `WithDPoP`.
- **BREAKING** `core/testutil`: `ParseSignedToken` is renamed `UnverifiedClaims`, which says what it does. **Migration:** rename the call.
- **BREAKING** `core/resource/verifier`: `VerifiedClaims.MayAct`, deprecated in 0.4.0. **Migration:** read the claim with `Claim("may_act")` if you still need it.

### Changed
- `mcp`, `mark3labs`: indirect dependencies are at their latest versions compatible with Go 1.26.
- **BREAKING** all modules: Go 1.26 is the floor. **Migration:** build with Go 1.26 or later.
- **BREAKING** `core/resource`: a bad, replayed or wrong-key proof answers `invalid_dpop_proof`, DPoP challenges list `algs`, a resource requiring DPoP answers a request with no token with the `DPoP` scheme, and challenge parameters are separated by commas. **Migration:** match `invalid_dpop_proof` where you match `invalid_token` for DPoP.
- **BREAKING** `http`: the DPoP scheme with an unbound token is refused, and `New` returns an error. **Migration:** send such a token as `Bearer`, and handle the error.
- **BREAKING** `mcp`, `mark3labs`: `ProtectedResourceMetadataHandler` is `PRMHandler`. **Migration:** rename the call.
- **BREAKING** `mark3labs`: `Adapter` no longer embeds the http adapter, `NewAdapterFromClientAndResource` takes `SessionOptions`, and existing sessions must restart because a session now binds to the client too. **Migration:** use the methods on `Adapter`, and pass `SessionOptions{}`.
- **BREAKING** `core/authplane`: `ClientCredentials` takes `ClientCredentialsInput`, and `FetchSettings`, `ClientAuthentication`, `TokenResponse`, `IntrospectionResponse` and `ASMetadata` are their own types. **Migration:** pass the input struct; `IntrospectionResponse.Audience` is now `[]string`.
- **BREAKING** `core/authplane`: `NewClient` refuses a non-positive breaker and a negative cache buffer, and a metadata failure is `ErrMetadataUnavailable`. **Migration:** fix those options, and match the sentinel.
- **BREAKING** `core/resource/verifier`: `MaxProofAge` over an hour fails construction, and a nil JWKS cache is an error. **Migration:** lower the value, and pass a cache.
- **BREAKING** `core/authplane`: `NewDPoPKeyMaterialFromKey` refuses a nil key or one that does not fit the algorithm. **Migration:** pass a matching key.
- **BREAKING** `core/resource/verifier`: `VerifyToken` returns `context.Canceled` or `context.DeadlineExceeded` when the caller's context ends during a JWKS wait or a revocation check, with status 503, including in fail-open mode. **Migration:** check for them where you check `ErrJWKSUnavailable`.
- **BREAKING** `core/authplane`: `FetchSettings.SSRFProtection` is replaced by `DisableSSRFProtection`, so a partly filled value no longer turns the guard off. **Migration:** drop `SSRFProtection: true`, and replace `SSRFProtection: false` with `DisableSSRFProtection: true`; a value that left it unset now protects, so add `AllowLocalhost` or `AllowPrivateNets` where you need them.
- **BREAKING** `core/resource`: a 5xx from token verification carries no `error` in its challenge, a `temporarily_unavailable` body and `Retry-After`, in place of `invalid_token`. **Migration:** treat it as retryable, and keep the token.
- **BREAKING** `core/resource/verifier`: a failed DPoP check now wins over revocation, so a revoked token with a bad proof gets the DPoP error. **Migration:** do not rely on `ErrTokenRevoked` for a request whose proof failed.
- **BREAKING** `core/authplane`: a JWKS holding only unreadable keys fails `NewClient`. **Migration:** check that the authorization server publishes at least one key this SDK can read.
- **BREAKING** `mcp`: moved to MCP go-sdk v1.8.0. A handler with `Stateless: true` speaks protocol 2026-07-28; a stateful one stays on 2025-11-25. **Migration:** upgrade your own go-sdk requirement and set `Stateless: true` to use 2026-07-28.
- **BREAKING** `mark3labs`: moved to mcp-go v1.5.0, which speaks protocol 2026-07-28. **Migration:** upgrade your own mcp-go requirement.
- **BREAKING** `mcp`: `ClaimsFromContext` and `TokenFromContext` no longer return an earlier request's values in a session, so a later call reads nil unless the server has `ReceivingMiddleware`; nil claims hold no scopes and their accessors return zero values. **Migration:** add `server.AddReceivingMiddleware(adapter.ReceivingMiddleware())`.
- **BREAKING** `mark3labs`: `AuthMiddleware` and `Middleware` answer 404 for a session not bound to the caller. **Migration:** add `server.WithSessionIdManagerResolver(adapter.SessionManager())`, or set `Options.AllowUnboundSessions`.
- `mcp`: a rejection body holds fixed text, an outage answers 503, and a token within core's clock skew is accepted, where the MCP SDK used to refuse it.
- `http`: a 5xx rejection logs at Error, and `PRMHandler` serves HEAD and OPTIONS and names the allowed methods.
- `core`: go-jose moves to v4.1.9.
- `core/resource`: `offline_access` no longer appears in `scopes_supported` or a challenge's `scope` (MCP authorization).
- **BREAKING** `core/resource/verifier`: a custom replay store receives an owner hash, the key thumbprint and a hash of the `jti`, a proof `jti` over 256 bytes is refused, one client and subject may hold 10,000 entries in the in-memory store, and a full or failing store gives `ErrDPoPReplayStoreUnavailable` with status 503. **Migration:** a custom store limits by the first segment of its key, the owner, and otherwise treats the key as opaque.
- **BREAKING** `core/resource/verifier`: `WithInboundDPoP` checks replay by default with an in-memory store. **Migration:** pass a distributed `ReplayStore` for several replicas, or `DisableReplayCheck: true` to opt out.
- **BREAKING** `core/resource/verifier`: a token whose `cnf` is not an object, or whose `cnf.jkt` is not a non-empty string, is refused. **Migration:** fix the issuer.
- **BREAKING** `core/resource/verifier`: a fail-closed revocation failure is `ErrRevocationUnavailable` with status 503, not `ErrTokenRevoked`. **Migration:** match the new error.
- **BREAKING** `core/resource/verifier`: `HasClaimValue` compares by JSON type, so `true` no longer matches `"true"`. **Migration:** pass the claim's own type.
- **BREAKING** `core/authplane`: more address ranges are refused on fetches, including `fd00:ec2::254`, `fd20:ce::254`, `168.63.129.16`, `fc00::/7`, NAT64, Teredo and `198.18.0.0/15`. **Migration:** set `AllowPrivateNets` for `fc00::/7`; the rest cannot be allowed.
- **BREAKING** `core/authplane`: with no `introspection_endpoint`, a fail-open verifier logs one warning and accepts, and a fail-closed one refuses every token. **Migration:** disable the check with `NullRevocationChecker` if that server cannot offer it.
- **BREAKING** `core/authplane`: an unsafe consent URL, such as a `javascript:` link, is dropped from `ConsentRequiredError`. **Migration:** have the server issue `https` consent URLs.
- **BREAKING** `core/authplane`: an `http` issuer is refused unless the fetch settings allow HTTP, and a loopback one also needs `AllowLocalhost`. **Migration:** use `https`, or `DevModeFetchSettings` in development.
- **BREAKING** `core/authplane`: `NewClient` fails if the JWKS endpoint answers something that is not a JWKS. **Migration:** fix the endpoint.
- **BREAKING** `core/resource/verifier`: a token with no `kid` is refused before any key lookup, even against a key with no `kid`. **Migration:** issue tokens with a `kid`.
- **BREAKING** `http`, `mark3labs`: `Middleware` answers the metadata path itself and never calls the next handler there; other methods get 405. **Migration:** serve nothing else on that path.
- **BREAKING** `core/resource`: `WithVerifierOptions` accumulates instead of replacing, so unrelated options keep auto-wired introspection. **Migration:** to turn it off, pass `WithRevocationChecker(NullRevocationChecker)`.
- **BREAKING** `core`: a DNS failure no longer matches the internal SSRF block error, and caller errors no longer count against the circuit breaker. **Migration:** none, unless you matched the error text.

## [0.4.0] - 2026-10-01

### Added
- `core/resource`: `WithResourceMetadataURL(string)` option and `Resource.ResourceMetadataURL()` accessor point the `resource_metadata` challenge parameter at an AS-hosted RFC 9728 document; the `http`, `mcp` and `mark3labs` adapters advertise it via `Options.ResourceMetadataURL`.
- `core/resource`: `AuthErrorResponseWithMetadata(err, resourceMetadataURL, realm...)` emits the RFC 9728 §5.1 `resource_metadata` parameter that the `http` adapter used to append itself; the header is byte-identical.
- `core/authplane`: `ErrAccessDenied` and `ErrInvalidTarget` sentinels for the token-endpoint errors `access_denied` (403, cross-client exchange not allowlisted on the target Resource) and `invalid_target` (400, RFC 8707 §2.2); match with `errors.Is`.
- `core/authplane`: the auto-wired introspection checker warns once per resource when the AS answers `active: false` for a locally valid token, pointing at the runtime-client requirement (authserver ≥ 0.1.2).
- `core/resource/verifier`: the fail-open revocation branch logs a `log/slog` warning carrying the checker error instead of accepting the token silently.
- `http`, `mcp`, `mark3labs`: every 401 `WWW-Authenticate` challenge now carries `scope="…"` listing the resource's configured scopes (RFC 6750 §3; MCP authorization spec SHOULD), omitted when none are configured. 403 challenges are unchanged.
- `core/resource`: `AuthErrorResponseVerbose(err error, realm ...string)` — `AuthErrorResponse` with the error's own message restored in the JSON `error_description`. A development aid: it discloses SDK-internal detail to unauthenticated callers, so do not use it in production.

### Fixed
- `core/resource`: a resource URI rejected at construction no longer appears unredacted in the error when it carries credentials; `errors.As(err, new(*url.Error))` keeps working.
- `core/internal/cache`: an unknown `kid` no longer costs one JWKS fetch per verification; forced refreshes have a retry floor of `min(jwksCacheTTL, 1m)`. **Impact:** a newly rotated `kid` can be rejected until that floor elapses.
- `core/internal/cache`: a server expiry at or before caching time no longer leaves the document permanently expired, and a server expiry longer than the configured interval is clamped to it.
- `core/resource`: the JSON error body for a request with no credentials no longer says `invalid_request`; like the challenge, it now omits `error`.

### Changed
- `core/authplane`: `access_denied` and `invalid_target` no longer count toward the circuit breaker — both are policy answers about the request, not an AS outage.
- **BREAKING** `core/resource`: `AuthErrorResponse` emits a fixed `error_description` per error code instead of the error's message; `RequireScopes` no longer lists missing scopes in the body. **Migration:** the `net/http` adapter logs the diagnostic at DEBUG; log `err` yourself elsewhere, or use `AuthErrorResponseVerbose` in development.
- **BREAKING** `core/resource`: `resource.New` rejects a resource URI with a literal space in the path, a `"` in the host, userinfo, or a query that is not valid RFC 3986. **Migration:** percent-encode the offending octets and remove credentials.
- **BREAKING** `core/resource`: `PRMURL()` now keeps the resource identifier's query in the derived PRM URL (RFC 9728 §3); `WellKnownPRMPath()` is unchanged. **Migration:** update any hard-coded expectation of the query-less URL.

### Deprecated
- `core/resource/verifier`: `(*VerifiedClaims).MayAct()` — authserver 0.2.0 no longer issues `may_act`; removed in the next minor. Parsing is unchanged until then.

## [0.3.0] - 2026-08-27

### Added
- `core/resource/verifier`: `ValidateIssuer(issuer string) error` — the RFC 8414 §2 issuer-shape rule, exported so every construction boundary applies one implementation rather than a copy. Rejects a query or fragment component, and requires an absolute URL with a scheme and host. `NewTokenVerifier`, `resource.New` and `authplane.NewClient` all route through it.
- `core/resource/verifier`: `ErrInvalidIssuer` sentinel, returned by everything that validates an issuer identifier. Match it with `errors.Is`.

### Fixed
- `core/resource/verifier`, `core/authplane`: an issuer rejected at construction is no longer echoed verbatim into the error. The query/fragment branch fires for exactly the shape that can carry a credential (`https://as.example.com?access_token=…`), and `net/url.Error` prints its URL field without redacting, so the raw identifier — query, fragment and any userinfo — reached whatever log the construction error landed in. Messages now carry scheme and host only. Parse failures are still wrapped with `%w`, so `errors.As(err, new(*url.Error))` keeps working; only the URL the error prints is substituted.
- `http`: the RFC 9728 PRM discovery bypass in the `net/http` adapter now compares `r.URL.EscapedPath()` against the escaped well-known path instead of the decoded `r.URL.Path`. A resource identifier carrying a percent-encoded octet (e.g. `%2F`) yields an escaped well-known path; comparing the decoded path let `%2F` collapse to `/`, the two sides disagreed, and the discovery endpoint stopped being bypassed and returned 401 even though RFC 9728 §3.2 requires it publicly reachable. The check is deliberately stricter than RFC 3986 §6.2.2.1 (a percent-encoded *unreserved* octet won't match its decoded form), an accepted trade-off since a conformant client signs the same octets the operator configured.

### Changed
- **BREAKING** `core/resource/verifier`, `core/resource`: `NewTokenVerifier` and `resource.New` now reject an issuer carrying a query or fragment component, and require the identifier to be an absolute URL with a scheme and host (RFC 8414 §2). Construction that succeeded in 0.2.0 — a relative reference such as `/tenant`, or an issuer with `?x=1` — now fails. `url.ParseRequestURI` alone accepted both: it takes a path-only reference, and it folds a fragment into `Path` rather than splitting it. **Migration:** pass the authorization server's issuer identifier exactly as published — absolute, `https`, no query, no fragment.
- **BREAKING** `core/authplane`: `NewClient` additionally requires the issuer to be absolute with a scheme and host, beyond the query/fragment rule below. This gate is not redundant with the verifier's: a `*Client` used only for token, introspection and revocation calls never constructs a `TokenVerifier`, so it is the only thing keeping a relative reference out of eager discovery. **Migration:** as above.
- **BREAKING** `core/authplane`: `ErrInvalidIssuer` is now an alias of `verifier.ErrInvalidIssuer` rather than its own sentinel. Two consequences for code that inspects it: the message changes from `authplane: invalid issuer` to `verifier: invalid issuer`, and `errors.Is(err, authplane.ErrInvalidIssuer)` now returns true for a rejection raised by the verifier, where it previously returned false. **Migration:** if you relied on the two sentinels being distinct to tell which layer rejected an identifier, that distinction is gone — both boundaries now apply the same rule, so match on the single sentinel and read the message for the specific violation. Code that only did `errors.Is(err, authplane.ErrInvalidIssuer)` on a `NewClient` error is unaffected.
- **BREAKING** `core/authplane`: `NewClient` now rejects an issuer containing a query or fragment component (RFC 8414 §2 forbids both) instead of passing it straight into metadata discovery. Previously the resource side rejected a fragment but the issuer had no such check, and the two discovery-URL builders diverged when either was present — the RFC 8414 builder silently dropped the issuer's query/fragment while the OIDC builder carried them along, so the two discovery attempts targeted different identities. Construction now fails immediately with a clear error. **Migration:** strip any query or fragment from the issuer you pass to `NewClient`; an issuer identifier never carries one.
- **BREAKING** `core/resource`: `resource.New` now rejects a resource URI containing a `#` (RFC 8707 §2 forbids a fragment in a resource indicator). `url.ParseRequestURI` does not split the fragment, so `https://api.example.com/mcp#frag` previously passed the scheme/host check and leaked the fragment into the derived PRM URL. This is a construction-time change on the exported constructor. **Migration:** remove any fragment from the resource URI you pass to `resource.New`.
- **BREAKING** `core/resource`: the RFC 9728 §3.1 PRM well-known URL now strips any terminating slash following the host component before inserting the well-known path suffix, so a resource identifier ending in `/mcp/` is served at (and derived by a conformant client as) `/.well-known/oauth-protected-resource/mcp` rather than `.../mcp/`. The resource identifier itself is unchanged — only the derived publication URL loses the slash. **Migration:** if you currently serve your PRM document at a trailing-slash well-known path, move it to the slash-stripped path (or route both) so RFC 9728 clients stop 404ing.
- **BREAKING** `core/resource`: `WellKnownPRMPath()` and `PRMURL()` now derive from the resource identifier's escaped path, so a percent-encoded octet (RFC 3986 §3.3 path data, e.g. `%2F`) is carried through verbatim instead of being decoded to `/`. A resource identifier such as `https://api.example.com/mcp%2Fx` therefore yields `.../oauth-protected-resource/mcp%2Fx` where 0.2.0 returned `.../mcp/x` — a visible output change on both exported methods. **Migration:** if you consume these values (routing the PRM handler, advertising `resource_metadata`), ensure your router matches the escaped path.
- **BREAKING** `core/internal/metadata`: the RFC 8414 §3.3 issuer check now compares the configured issuer and the metadata document's `issuer` byte-for-byte (§4: code-point-for-code-point, no normalization) instead of trailing-slash-insensitively. A document whose issuer differs from the configured issuer only by a trailing slash is now rejected as a mismatch. Because discovery is eager, this surfaces at `NewClient` as `metadata: issuer mismatch` — construction fails immediately, not at the first token verification. **Migration:** If your configured issuer differs from your authorization server's actual identifier by a trailing slash, correct the config — the SDK no longer silently reconciles them.
- **BREAKING** `core/resource/verifier`: the token verifier stores the issuer passed to `NewTokenVerifier` verbatim and matches a token's `iss` claim byte-for-byte (RFC 8414 §4: code-point-for-code-point, no normalization) instead of trailing-slash-insensitively. A token whose `iss` differs from the configured issuer only by a trailing slash is now an `ErrIssuerMismatch`. **Migration:** If the issuer you pass to `NewTokenVerifier` differs from your authorization server's actual identifier by a trailing slash, correct it — the SDK no longer silently reconciles them.

## [0.2.0] - 2026-07-21

### Added
- `core/resource/verifier`: `(*VerifiedClaims).RequireScopes(scopes ...string) error` plural helper. Returns `nil` on empty input, and on failure wraps `ErrInsufficientScope` naming every missing scope plus the scopes the token does carry, so an adapter can surface it verbatim in the `WWW-Authenticate` `error_description`.
- `core/resource/verifier`: `ErrMultipleDpopProofs` sentinel for RFC 9449 §4.3 #1 violations. `core/resource.AuthErrorResponse` maps it to a `DPoP error="invalid_dpop_proof"` 401 challenge per RFC 9449 §7.1.
- `core/resource/verifier`: `NewDPoPContext(method, url, dpopHeaderValues []string) (*DPoPContext, error)` factory — the canonical §4.3 #1 enforcement boundary. Filters blanks, splits on `,` defensively for proxies that pre-join duplicate headers, and returns `ErrMultipleDpopProofs` on more than one non-blank value.
- `core/resource/verifier`: `(*DPoPContext).Proof()` nil-safe accessor returning the single proof (or `""` when none).
- `mark3labs` module: adapter for [`mark3labs/mcp-go`](https://github.com/mark3labs/mcp-go). Wraps `*authplanehttp.Adapter` so consumers get bearer + DPoP auth, RFC 9728 PRM, and `HTTPContextFunc` integration for the mark3labs HTTP server. `HTTPContextFunc` takes `WithForwardedContextKeys(keys ...any)` and `WithContextForwarding(fn)` options to propagate values (request IDs, tracing spans, …) from the upstream request context onto the per-tool-call MCP context. See `mark3labs/docs/user-guide.md`.
- `core/resource`: `Resource.PRMURL()` returns the precomputed absolute Protected Resource Metadata URL as a single infallible source of truth.
- `core/resource`: `Resource.PRMConfig()` returns the Protected Resource Metadata as a typed `PRMConfig` struct, for feeding into third-party PRM-serving handlers (e.g. mark3labs/mcp-go's `NewProtectedResourceMetadataHandler`) without going through the dynamic `PRMResponse` map.
- `core/authplane`: `TokenResponse`/`IntrospectionResponse` expose the RFC 9449 §6 confirmation — `Cnf json.RawMessage` (raw `cnf`, verbatim) and `CnfJkt string` (DPoP thumbprint from `cnf.jkt`, empty when unbound). Derived at parse time and preserved across `TokenCache` hits.

### Fixed
- `core/resource/verifier`: `validateHTU` compares `EscapedPath()` instead of `Path`, so an encoded `%2F` is no longer treated as equivalent to a literal `/`. The previous comparison conflated distinct request targets, weakening the RFC 9449 §4.3 `htu` binding (RFC 3986 §6.2.2.2 only permits decoding *unreserved* characters when comparing URLs).
- `core/resource/verifier`: `validateHTU` strips an explicit default port (`:80` for http, `:443` for https) on both sides before comparing (RFC 9110 §7.2), so a resource configured as `http://api.example.com:80/mcp` no longer mismatches every client that signs the port-less form.
- `core/resource/verifier`: `validateHTU` collapses an empty path to `/` on both sides before comparing, so a client signing a bare-origin htu (e.g. `https://host`) no longer fails against a server where every inbound `r.URL.EscapedPath()` is at least `/`.
- `core/internal/cache`: `TokenCache.Set` distinguishes a missing `expires_in` from `expires_in: 0` (RFC 6749 §5.1) — nil applies the default TTL, `0` is refused as born-expired instead of cached for the default hour.
- `core/internal/dpop`: `NormalizePath` upper-cases percent-encoded hex triplets (RFC 3986 §6.2.2.1) on both comparison sides, so a proof signed with `%2f` matches a request reconstructed with `%2F`.

### Changed
- **BREAKING (pre-1.0)** `core/authplane`: `TokenResponse.ExpiresIn` changes from `int64` to `*int64`, so a response that omits `expires_in` is now `nil` rather than `0`. This distinguishes an absent field from an explicit `expires_in: 0` (RFC 6749 §5.1 permits a deliberately-expired one-shot token) and aligns the Go shape with the optional `expires_in` wire contract (absent vs. `0` vs. positive). **Migration:** any caller reading `resp.ExpiresIn` directly (arithmetic, comparison, formatting) must dereference and nil-check; treat `nil` as "apply your default" and `*v == 0` as "already expired".
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
