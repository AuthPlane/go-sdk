# Threat model

What this SDK defends against, what it leaves to you, and what it assumes. Report a gap through [SECURITY.md](../SECURITY.md).

## Assets

- The decision to accept a request: a forged, expired, wrong-audience or revoked token must not pass.
- Credentials the SDK holds or handles: client secrets, signing keys, DPoP keys, access and subject tokens.
- The network position of the host: the SDK must not be used to reach private addresses.

## Attackers and what stops them

| Attacker | Attempt | Defense |
|---|---|---|
| Unauthenticated caller | Forged or altered token | Signature check against the discovered keys; `none` and HMAC refused; issuer, audience, expiry, not-before and `typ` checked |
| Unauthenticated caller | Forcing key fetches with made-up `kid` values | Single-flight fetches with refresh floors |
| Holder of a stolen token | Replay of a sender-bound token | DPoP proof bound to key, method, URL and token, with replay detection |
| Authenticated client | Filling the replay store | A limit per signed client and subject. Ten such pairs can still fill the in-memory store, so size a store for open sign-up or registration |
| Malicious or compromised authorization server metadata | Pointing fetches at internal addresses | Address checks, DNS pinning, no redirects, size limits, unless `DisableSSRFProtection` is set |
| Caller with a network foothold | Token theft through logs or errors | Tokens and secrets are redacted when formatted, and server text in errors is cleaned and shortened |

## What this SDK does not do

- It does not authenticate your users or issue tokens.
- It does not decide what a verified caller may do, beyond the scope checks you ask for.
- Revocation is only as fresh as the check you configure, and by default a failed check accepts the token (fail-open). Use `WithFailClosed` where that is wrong for you.
- `RequireToolScopes` passes a tool it does not list, unless you use `RefuseUnlistedTools`.
- A cached token exchange result ends at its source JWT's `exp`, but an opaque subject token has no `exp` to read, so it lasts until `Revoke` or the result's own expiry.
- `Revoke` follows exchanges through entries still cached. A result whose parent entry was replaced or evicted earlier is no longer linked, and lasts until its own expiry.
- An introspection answer is active only with exactly one member named `active`, holding `true`, so a server sending a case-variant `Active` member alongside it has its tokens refused.
- The in-memory replay store protects one process. Several replicas need a shared store.

## Assumptions

- The issuer you configure is one you trust, and its metadata and keys are served over HTTPS.
- Your process and its memory are not compromised.
- The clock is correct to within the configured skew.
