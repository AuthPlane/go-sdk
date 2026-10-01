package httputil

import (
	"net/http"
	"regexp"
	"strings"
)

// WWWAuthenticateScopeHint wraps an http.ResponseWriter to append
// `scope="..."` to the WWW-Authenticate header of a 401 response (RFC 6750
// §3). The MCP authorization spec says the server SHOULD name the scopes to
// request on the first challenge; the MCP go-sdk's auth.RequireBearerToken
// writes only `Bearer resource_metadata=...` and offers no hook for further
// params, so the header is amended here before the status line goes out.
//
// Scope is the space-separated list to advertise; when empty the writer is a
// pass-through. Only a 401 is amended — a 403 names route-specific scopes.
//
// The wrapper sits in front of the whole handler chain, so it also sees 401s
// written by the wrapped application. Those are left alone: an amended
// challenge is only correct for one this package knows the shape of, so the
// header must already be present and carry the Bearer scheme.
//
// http.Flusher is forwarded so that SSE streaming used by the MCP streamable
// transport continues to work correctly.
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
			h.Set("WWW-Authenticate", v+sep+`scope="`+sanitizeParamValue(w.Scope)+`"`)
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

// sanitizeParamValue makes a value safe to splice into a WWW-Authenticate
// quoted-string (RFC 9110 §5.6.4): CR, LF, `"` and `\` are each replaced by a
// space, and the result is trimmed. Substitution rather than deletion is what
// keeps `a"b` two scope tokens instead of silently fusing it into one — none
// of these octets is legal in a scope-token (RFC 6749 §3.3) or in the URI
// derived for resource_metadata, so no valid value is altered.
func sanitizeParamValue(v string) string {
	return strings.TrimSpace(paramValueSanitizer.ReplaceAllString(v, " "))
}

// A run collapses to one space: `\"` is one offense, not two, and should not
// widen the value by an extra space.
var paramValueSanitizer = regexp.MustCompile(`[\r\n"\\]+`)

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
