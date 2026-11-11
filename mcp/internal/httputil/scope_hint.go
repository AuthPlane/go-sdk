package httputil

import (
	"net/http"
	"strings"

	"github.com/authplane/go-sdk/core/resource"
)

// WWWAuthenticateScopeHint wraps an http.ResponseWriter to append
// `scope="..."` to the WWW-Authenticate header of a 401 response (RFC 6750
// §3). The MCP authorization spec says the server SHOULD name the scopes to
// request on the first challenge; the MCP go-sdk's auth.RequireBearerToken
// writes only `Bearer resource_metadata=...` and offers no hook for further
// params, so the header is amended here before the status line goes out.
type WWWAuthenticateScopeHint struct {
	http.ResponseWriter
	Scope string
}

// WriteHeader appends the scope param to a 401's existing Bearer
// WWW-Authenticate header before writing the status line. The separator is a
// space when the challenge carries no auth-param yet and `, ` otherwise
// (RFC 9110 §11.1). A missing header or a non-Bearer scheme passes through:
// synthesizing a Bearer challenge here would advertise one without
// resource_metadata, and appending to another scheme is meaningless.
func (w *WWWAuthenticateScopeHint) WriteHeader(code int) {
	if code == http.StatusUnauthorized && w.Scope != "" {
		h := w.Header()
		if v := h.Get("WWW-Authenticate"); isBearerChallenge(v) {
			sep := " "
			if strings.Contains(v, "=") {
				sep = ", "
			}
			h.Set("WWW-Authenticate", v+sep+`scope="`+resource.SanitizeChallengeValue(w.Scope)+`"`)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

// isBearerChallenge reports whether v is a WWW-Authenticate value whose
// auth-scheme is Bearer. RFC 9110 §11.1 makes the scheme case-insensitive.
func isBearerChallenge(v string) bool {
	if v == "" {
		return false
	}
	scheme, _, _ := strings.Cut(v, " ")
	return strings.EqualFold(scheme, "Bearer")
}

// Flush forwards to the underlying ResponseWriter's Flusher if available.
// Required for SSE streaming used by the MCP streamable HTTP transport.
func (w *WWWAuthenticateScopeHint) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the wrapped ResponseWriter so that http.ResponseController
// can reach the real writer for SetWriteDeadline, Hijack and friends.
func (w *WWWAuthenticateScopeHint) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
