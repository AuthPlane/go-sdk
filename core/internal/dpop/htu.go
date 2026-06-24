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

// NormalizePath collapses an empty path to "/" and upper-cases the hex
// digits of percent-encoded triplets per RFC 3986 §6.2.2.1.
//
// Empty-path collapse: the Go net/http server hands every request a
// path of at least "/", so the asymmetry only bites when an htu is
// built from a bare-origin URL — a proof signed for `https://host`
// would otherwise fail against a request the server sees as
// `https://host/`.
//
// Hex upper-casing: RFC 3986 §6.2.2.1 treats `%2f` and `%2F` as
// equivalent and recommends upper-case as the canonical form. The
// verifier (`core/resource/verifier/dpop.go`) routes both the proof's
// htu and the reconstructed request URL through `NormalizePath` before
// comparing, so canonicalizing hex casing on both sides lets a proof
// signed with `%2f` match a request whose framework emits `%2F` (or
// vice versa) without requiring identical raw casing across frameworks.
// Note: neither Go's `net/url.EscapedPath()` nor WHATWG `URL.pathname`
// rewrites the case of existing `%XX` triplets — the byte-for-byte
// equality at the comparison site is produced *here*, not by the parser.
func NormalizePath(p string) string {
	if p == "" {
		return "/"
	}
	return upperHexPercent(p)
}

// upperHexPercent rewrites every well-formed `%XX` triplet so the two
// hex digits are upper-case, leaving bytes outside such triplets
// (including a bare `%` not followed by two hex chars) untouched.
func upperHexPercent(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] != '%' {
			continue
		}
		if !isHex(b[i+1]) || !isHex(b[i+2]) {
			continue
		}
		b[i+1] = upperHex(b[i+1])
		b[i+2] = upperHex(b[i+2])
		i += 2
	}
	return string(b)
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func upperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - ('a' - 'A')
	}
	return c
}
