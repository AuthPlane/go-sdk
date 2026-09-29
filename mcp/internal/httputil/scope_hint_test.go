package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWWWAuthenticateScopeHint pins the separator and gating of the scope
// hint: appended with `, ` after an existing param, with a space after a bare
// scheme, and left alone on any status other than 401, when no scope is
// configured, when upstream wrote no challenge at all, or when the challenge
// belongs to another auth-scheme.
func TestWWWAuthenticateScopeHint(t *testing.T) {
	const prm = `Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource/mcp"`
	tests := []struct {
		name     string
		scope    string
		code     int
		existing string
		want     string
	}{
		{
			name:     "appended after resource_metadata",
			scope:    "tools/add tools/multiply",
			code:     http.StatusUnauthorized,
			existing: prm,
			want:     prm + `, scope="tools/add tools/multiply"`,
		},
		{
			name:     "space after bare scheme",
			scope:    "tools/add",
			code:     http.StatusUnauthorized,
			existing: "Bearer",
			want:     `Bearer scope="tools/add"`,
		},
		{
			name:  "no challenge from upstream is a pass-through",
			scope: "tools/add",
			code:  http.StatusUnauthorized,
			want:  "",
		},
		{
			name:     "another auth-scheme is a pass-through",
			scope:    "tools/add",
			code:     http.StatusUnauthorized,
			existing: `Basic realm="admin"`,
			want:     `Basic realm="admin"`,
		},
		{
			name:     "scheme match is case-insensitive",
			scope:    "tools/add",
			code:     http.StatusUnauthorized,
			existing: "bearer",
			want:     `bearer scope="tools/add"`,
		},
		{
			// Substituted, not deleted, and a run collapses to one space, so
			// `a"b` stays two scope tokens rather than fusing into one.
			name:     "quoted-string octets become a space in the scope",
			scope:    `tools/add" x=\"y`,
			code:     http.StatusUnauthorized,
			existing: prm,
			want:     prm + `, scope="tools/add  x= y"`,
		},
		{
			name:     "CR and LF cannot split the header",
			scope:    "tools/add\r\nX-Injected: 1",
			code:     http.StatusUnauthorized,
			existing: prm,
			want:     prm + `, scope="tools/add X-Injected: 1"`,
		},
		{
			name:     "surrounding offenses are trimmed, not left as spaces",
			scope:    `"tools/add"`,
			code:     http.StatusUnauthorized,
			existing: prm,
			want:     prm + `, scope="tools/add"`,
		},
		{
			name:     "403 is left alone",
			scope:    "tools/add",
			code:     http.StatusForbidden,
			existing: prm,
			want:     prm,
		},
		{
			name:     "empty scope is a pass-through",
			code:     http.StatusUnauthorized,
			existing: prm,
			want:     prm,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			w := &WWWAuthenticateScopeHint{ResponseWriter: rec, Scope: tt.scope}
			if tt.existing != "" {
				w.Header().Set("WWW-Authenticate", tt.existing)
			}
			w.WriteHeader(tt.code)
			if got := rec.Header().Get("WWW-Authenticate"); got != tt.want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.want)
			}
			if rec.Code != tt.code {
				t.Errorf("status = %d, want %d", rec.Code, tt.code)
			}
		})
	}
}

// TestWWWAuthenticateScopeHintFlush verifies Flush is forwarded so SSE
// streaming keeps working through the wrapper.
func TestWWWAuthenticateScopeHintFlush(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &WWWAuthenticateScopeHint{ResponseWriter: rec, Scope: "tools/add"}
	w.Flush()
	if !rec.Flushed {
		t.Error("Flush was not forwarded to the underlying ResponseWriter")
	}
}
