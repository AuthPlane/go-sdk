// Package dpop holds shared internal helpers for DPoP htu normalization
// (RFC 9449 §4.3) used by both the outbound signer (`core/authplane`) and
// the inbound verifier (`core/resource/verifier`). Centralizing the rules
// here keeps the two sides from drifting: if the signer emits an htu whose
// authority the verifier won't accept (or vice versa), every DPoP-bound
// proof from a client to a resource silently breaks.
package dpop

import (
	"net/url"
	"strings"
)

// NormalizeHost returns u.Host with an explicit default port removed
// (`:80` for `http`, `:443` for `https`), per RFC 9110 §7.2. IPv6 literals
// stay bracketed. Non-default ports and other schemes are returned as-is.
//
// The signer side calls this to mirror the outbound Host header (where an
// explicit default port is omitted); the verifier side calls it on both
// the proof's htu and the reconstructed request URL before comparing them.
//
// Precondition: when used to compare two URLs (verifier side), the caller
// must have already verified scheme equality between them. The strip rule
// is scheme-conditional — `:80` is "default" only when scheme is `http` —
// so applying NormalizeHost across two URLs with different schemes can
// erase a port on one side but not the other, producing a spurious match.
// `validateHTU` enforces the scheme check above its NormalizeHost call.
func NormalizeHost(u *url.URL) string {
	port := u.Port()
	if port == "" {
		return u.Host
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		host := u.Hostname()
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return u.Host
}

// NormalizePath collapses an empty path to "/" to match the ts and python
// reference SDKs (`parsed.pathname || "/"` / `parsed.path or "/"`). The Go
// net/http server hands every request a path of at least "/", so the
// asymmetry only bites when an htu is built from a bare-origin URL — a
// Go-signed proof for `https://host` would otherwise fail against a request
// the server sees as `https://host/`.
//
// Percent-encoded triplets are intentionally NOT case-folded. RFC 3986
// §6.2.2.1 says that the hex digits within a triplet (`%2f` vs `%2F`)
// *should* be normalized to upper-case when comparing URIs, but the verifier
// compares the path byte-for-byte. Folding case unilaterally would let the
// verifier accept a proof that a byte-exact signer rejects (and vice-versa)
// on the exact path the §4.3 binding is meant to lock down. Holding the
// byte-equality contract until an aligned RFC §6.2.2.1 pass lands.
func NormalizePath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}
