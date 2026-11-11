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
