package httputil

import (
	"net/http"
	"strings"
)

// WWWAuthenticateQuoter wraps an http.ResponseWriter to ensure all auth-param
// values in the WWW-Authenticate header are properly quoted per RFC 6750 §3.1.
//
// An auth-param value must be a quoted-string if it contains any character that
// is not a valid HTTP token character (RFC 7230 §3.2.6). The MCP go-sdk emits
// these values bare (go-sdk bug: auth/auth.go:77), so we fix them before the
// headers reach the client.
//
// http.Flusher is forwarded so that SSE streaming used by the MCP streamable
// transport continues to work correctly.
type WWWAuthenticateQuoter struct {
	http.ResponseWriter
}

// WriteHeader quotes RFC 6750 WWW-Authenticate parameter values before
// writing the status line, ensuring values containing special characters
// are properly double-quoted per RFC 9110 §11.2.
func (w *WWWAuthenticateQuoter) WriteHeader(code int) {
	h := w.Header()
	if v := h.Get("WWW-Authenticate"); v != "" {
		h.Set("WWW-Authenticate", QuoteWWWAuthenticateParams(v))
	}
	w.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying ResponseWriter's Flusher if available.
// Required for SSE streaming used by the MCP streamable HTTP transport.
func (w *WWWAuthenticateQuoter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// QuoteWWWAuthenticateParams ensures every key=value param in a WWW-Authenticate
// header value is quoted if the value is not a valid HTTP token.
// For example:  Bearer resource_metadata=http://x  →  Bearer resource_metadata="http://x"
func QuoteWWWAuthenticateParams(header string) string {
	// Split on the first space to get the scheme ("Bearer") and the rest.
	scheme, rest, ok := strings.Cut(header, " ")
	if !ok {
		return header
	}
	var b strings.Builder
	b.WriteString(scheme)
	for part := range strings.SplitSeq(rest, ", ") {
		b.WriteString(" ")
		key, val, hasEq := strings.Cut(part, "=")
		if !hasEq || strings.HasPrefix(val, `"`) {
			// No value or already quoted — leave as-is.
			b.WriteString(part)
		} else if needsQuoting(val) {
			b.WriteString(key)
			b.WriteByte('=')
			b.WriteByte('"')
			b.WriteString(val)
			b.WriteByte('"')
		} else {
			b.WriteString(part)
		}
	}
	return b.String()
}

// needsQuoting reports whether s contains any character that is not a valid
// HTTP token character (RFC 7230 §3.2.6), and therefore requires quoting.
func needsQuoting(s string) bool {
	const tokenChars = "!#$%&'*+-.^_`|~" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
		"0123456789"
	for _, c := range s {
		if !strings.ContainsRune(tokenChars, c) {
			return true
		}
	}
	return false
}
