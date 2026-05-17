package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestQuoteWWWAuthenticateParams verifies that auth-param values containing
// non-token characters are quoted per RFC 6750 §3.1 / RFC 7230 §3.2.6.
func TestQuoteWWWAuthenticateParams(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "URL value gets quoted",
			input: `Bearer resource_metadata=http://localhost:8080/.well-known/oauth-protected-resource`,
			want:  `Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"`,
		},
		{
			name:  "already quoted value is left unchanged",
			input: `Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"`,
			want:  `Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"`,
		},
		{
			name:  "plain token value needs no quoting",
			input: `Bearer realm=example`,
			want:  `Bearer realm=example`,
		},
		{
			name:  "no params — scheme only",
			input: `Bearer`,
			want:  `Bearer`,
		},
		{
			name:  "multiple params — only non-token values quoted",
			input: `Bearer realm=example, resource_metadata=http://as.example.com/meta`,
			want:  `Bearer realm=example resource_metadata="http://as.example.com/meta"`,
		},
		{
			name:  "https URL gets quoted",
			input: `Bearer resource_metadata=https://as.example.com/.well-known/resource`,
			want:  `Bearer resource_metadata="https://as.example.com/.well-known/resource"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := QuoteWWWAuthenticateParams(tc.input)
			if got != tc.want {
				t.Errorf("QuoteWWWAuthenticateParams(%q)\n got  %q\n want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestWWWAuthenticateQuoterWriteHeader verifies that the response writer wrapper
// fixes the WWW-Authenticate header before it is sent to the client.
func TestWWWAuthenticateQuoterWriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &WWWAuthenticateQuoter{ResponseWriter: rec}

	w.Header().Set("WWW-Authenticate", `Bearer resource_metadata=http://localhost:9000/.well-known/resource`)
	w.WriteHeader(http.StatusUnauthorized)

	got := rec.Header().Get("WWW-Authenticate")
	want := `Bearer resource_metadata="http://localhost:9000/.well-known/resource"`
	if got != want {
		t.Errorf("WWW-Authenticate header\n got  %q\n want %q", got, want)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestWWWAuthenticateQuoterAlreadyQuoted verifies that an already-correct header
// is not double-quoted.
func TestWWWAuthenticateQuoterAlreadyQuoted(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &WWWAuthenticateQuoter{ResponseWriter: rec}

	want := `Bearer resource_metadata="http://localhost:9000/.well-known/resource"`
	w.Header().Set("WWW-Authenticate", want)
	w.WriteHeader(http.StatusUnauthorized)

	got := rec.Header().Get("WWW-Authenticate")
	if got != want {
		t.Errorf("WWW-Authenticate header\n got  %q\n want %q", got, want)
	}
}

// TestWWWAuthenticateQuoterFlush verifies that Flush is forwarded to the
// underlying ResponseWriter so SSE streaming works correctly.
func TestWWWAuthenticateQuoterFlush(t *testing.T) {
	rec := httptest.NewRecorder() // httptest.ResponseRecorder implements http.Flusher
	w := &WWWAuthenticateQuoter{ResponseWriter: rec}

	w.Flush() // must not panic and must call the underlying Flusher

	if !rec.Flushed {
		t.Error("Flush() did not flush the underlying ResponseWriter")
	}
}
