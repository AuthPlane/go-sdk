package resource_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
)

// TestAuthErrorResponse_MultipleDpopProofs_MapsToInvalidDpopProof pins
// the RFC 9449 §4.3 #1 / §7.1 mapping at the package level rather than
// in `core/conformancetests/rfc6750_test.go`. The shared catalog entry
// `rfc6750-error-response-must-map-error-codes` only enumerates
// `dpop_error → invalid_token / DPoP`; we don't add the
// `invalid_dpop_proof` row to the conformance suite until the catalog
// gains a `rfc9449-verifier-must-reject-multiple-dpop-headers` entry.
// Until then the assertion lives here.
func TestAuthErrorResponse_MultipleDpopProofs_MapsToInvalidDpopProof(t *testing.T) {
	status, headers, _ := resource.AuthErrorResponse(verifier.ErrMultipleDpopProofs)

	if status != 401 {
		t.Errorf("status = %d, want 401", status)
	}
	wwwAuth := headers["WWW-Authenticate"]
	if !strings.HasPrefix(wwwAuth, "DPoP") {
		t.Errorf("WWW-Authenticate = %q, want DPoP-scheme challenge", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `error="invalid_dpop_proof"`) {
		t.Errorf("WWW-Authenticate = %q, want invalid_dpop_proof error code", wwwAuth)
	}
}

// legacyChallengeWithMetadata reproduces the composition the http adapter
// performed before AuthErrorResponseWithMetadata existed: take the challenge
// AuthErrorResponse emits, then append resource_metadata with a space when no
// auth-param is present yet and ", " otherwise. It is the reference the tests
// below compare against, so a change to the emitter that alters a single byte
// of the wire format fails here rather than on a client.
func legacyChallengeWithMetadata(challenge, metadataURL string) string {
	if metadataURL == "" {
		return challenge
	}
	if challenge == "" {
		challenge = "Bearer"
	}
	sep := " "
	if strings.Contains(challenge, "=") {
		sep = ", "
	}
	return challenge + sep + `resource_metadata="` + metadataURL + `"`
}

// TestAuthErrorResponseWithMetadata_MatchesPreviousAdapterComposition pins the
// emitter move: carrying the resource_metadata parameter here instead of in the
// http adapter must not change one byte of the emitted header. Every challenge shape
// the adapter can produce is covered, the bare-Bearer no-token case included —
// that is the one whose separator is a space rather than a comma, and the one
// MCP clients parse on the very first unauthenticated request.
func TestAuthErrorResponseWithMetadata_MatchesPreviousAdapterComposition(t *testing.T) {
	const metadataURL = "https://api.example.com/.well-known/oauth-protected-resource/mcp"
	tests := []struct {
		name string
		err  error
	}{
		{"no token (bare Bearer)", verifier.ErrTokenMissing},
		{"invalid token", verifier.ErrInvalidSignature},
		{"expired token", verifier.ErrTokenExpired},
		{"insufficient scope", &resource.ScopeError{RequiredScopes: []string{"tools/admin"}, Err: verifier.ErrInsufficientScope}},
		{"insufficient scope, several", &resource.ScopeError{RequiredScopes: []string{"tools/admin", "tools/superuser"}, Err: verifier.ErrInsufficientScope}},
		{"DPoP required", verifier.ErrDPoPRequired},
		{"DPoP invalid", verifier.ErrDPoPInvalid},
		{"multiple DPoP proofs", verifier.ErrMultipleDpopProofs},
		{"DPoP not supported (Bearer scheme)", verifier.ErrDPoPNotSupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldStatus, oldHeaders, oldBody := resource.AuthErrorResponse(tt.err)
			want := legacyChallengeWithMetadata(oldHeaders["WWW-Authenticate"], metadataURL)

			status, headers, body := resource.AuthErrorResponseWithMetadata(tt.err, metadataURL)
			if got := headers["WWW-Authenticate"]; got != want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, want)
			}
			if status != oldStatus {
				t.Errorf("status = %d, want %d", status, oldStatus)
			}
			if body != oldBody {
				t.Errorf("body = %q, want %q", body, oldBody)
			}
			if got := headers["Content-Type"]; got != oldHeaders["Content-Type"] {
				t.Errorf("Content-Type = %q, want %q", got, oldHeaders["Content-Type"])
			}
		})
	}
}

// descriptionOf decodes the error_description member of an AuthErrorResponse
// body, failing the test if the body is not the JSON object this package
// documents.
func descriptionOf(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("body is not valid JSON: %v — body: %s", err, body)
	}
	return parsed.ErrorDescription
}

// TestAuthErrorResponse_DescriptionNeverCarriesTheErrorMessage is the point of
// the fixed description table: the body is served to a caller who has not
// authenticated, so the detail the verifier names — the unknown `kid`, the
// audience the resource expects, the rejected `typ` — must not travel with it.
// The assertion is on the wire body rather than on the error, because the
// error deliberately keeps its message for the resource server to log.
func TestAuthErrorResponse_DescriptionNeverCarriesTheErrorMessage(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		secret string
	}{
		{
			name:   "audience mismatch does not disclose the expected aud",
			err:    fmt.Errorf("%w: token aud does not include %q", verifier.ErrAudienceMismatch, "https://api.example.com/internal"),
			secret: "https://api.example.com/internal",
		},
		{
			name:   "signature failure does not disclose the unknown kid",
			err:    fmt.Errorf("%w: no key for kid %q", verifier.ErrInvalidSignature, "2026-09-rotation-key"),
			secret: "2026-09-rotation-key",
		},
		{
			name:   "claim rejection does not disclose the rejected typ",
			err:    fmt.Errorf("%w: unexpected typ %q", verifier.ErrInvalidClaims, "application/vnd.internal+jwt"),
			secret: "application/vnd.internal+jwt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, body := resource.AuthErrorResponse(tt.err)
			if strings.Contains(body, tt.secret) {
				t.Errorf("body = %s, want it not to disclose %q", body, tt.secret)
			}
			if got, want := descriptionOf(t, body), "The access token is missing or not valid for this resource"; got != want {
				t.Errorf("error_description = %q, want %q", got, want)
			}
			if !strings.Contains(tt.err.Error(), tt.secret) {
				t.Errorf("err = %q, want the detail kept on the error for the server to log", tt.err)
			}
		})
	}
}

// TestAuthErrorResponseVerbose_BodyIsValidJSONWithControlBytes: the verbose
// form puts the underlying error message back on the wire, and the verifier
// interpolates token-controlled header values into those messages. Go's %q
// would render a control byte as a Go escape that is not a JSON escape, so the
// body has to be marshaled.
func TestAuthErrorResponseVerbose_BodyIsValidJSONWithControlBytes(t *testing.T) {
	err := fmt.Errorf("%w: token type must be \"at+jwt\", got \"a\x7fb\"", verifier.ErrInvalidClaims)

	_, _, body := resource.AuthErrorResponseVerbose(err)

	var decoded struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if jsonErr := json.Unmarshal([]byte(body), &decoded); jsonErr != nil {
		t.Fatalf("body is not valid JSON: %v (body = %s)", jsonErr, body)
	}
	if !strings.Contains(decoded.Description, "a\x7fb") {
		t.Errorf("error_description = %q, want it to carry the offending value", decoded.Description)
	}
}

// TestAuthErrorResponse_DescriptionIsFixedPerErrorCode pins the exact sentence
// emitted for each error code. The strings are a wire contract, so a rewording
// here is a wire change and should fail this test first.
func TestAuthErrorResponse_DescriptionIsFixedPerErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"invalid_token", verifier.ErrTokenExpired, "The access token is missing or not valid for this resource"},
		{"insufficient_scope", verifier.ErrInsufficientScope, "The access token does not carry the scope this operation requires"},
		{"invalid_dpop_proof", verifier.ErrMultipleDpopProofs, "The DPoP proof is missing or not valid for this request"},
		// No challenge `error` parameter (RFC 6750 §3.1), and none in the body
		// either; the description comes from missingCredentialsDescription
		// rather than from a row keyed by a code neither half names.
		{"no credentials", verifier.ErrTokenMissing, "The request did not carry an access token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, body := resource.AuthErrorResponse(tt.err)
			if got := descriptionOf(t, body); got != tt.want {
				t.Errorf("error_description = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAuthErrorResponseWithMetadata_RealmAndSeparators pins the parameter order
// and separators directly, rather than against the reference composition: the
// metadata parameter goes last, after realm, error and scope.
func TestAuthErrorResponseWithMetadata_RealmAndSeparators(t *testing.T) {
	const metadataURL = "https://as.example.com/.well-known/oauth-protected-resource/mcp"
	tests := []struct {
		name  string
		err   error
		realm []string
		want  string
	}{
		{
			name: "no token — space separator after the bare scheme",
			err:  verifier.ErrTokenMissing,
			want: `Bearer resource_metadata="` + metadataURL + `"`,
		},
		{
			name: "invalid token — comma after the error param",
			err:  verifier.ErrInvalidSignature,
			want: `Bearer error="invalid_token", resource_metadata="` + metadataURL + `"`,
		},
		{
			name: "insufficient scope — metadata last, after scope",
			err:  &resource.ScopeError{RequiredScopes: []string{"tools/admin"}, Err: verifier.ErrInsufficientScope},
			want: `Bearer error="insufficient_scope", scope="tools/admin", resource_metadata="` + metadataURL + `"`,
		},
		{
			name:  "realm present — metadata still last",
			err:   verifier.ErrTokenMissing,
			realm: []string{"api"},
			want:  `Bearer realm="api", resource_metadata="` + metadataURL + `"`,
		},
		{
			name: "multiple DPoP proofs — DPoP scheme keeps the parameter",
			err:  verifier.ErrMultipleDpopProofs,
			want: `DPoP error="invalid_dpop_proof", resource_metadata="` + metadataURL + `"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, headers, _ := resource.AuthErrorResponseWithMetadata(tt.err, metadataURL, tt.realm...)
			if got := headers["WWW-Authenticate"]; got != tt.want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAuthErrorResponseWithMetadata_EmptyURLIsAuthErrorResponse: an empty URL
// emits the challenge unchanged, so the metadata-carrying function is a drop-in
// for callers that have no document to advertise.
func TestAuthErrorResponseWithMetadata_EmptyURLIsAuthErrorResponse(t *testing.T) {
	for _, err := range []error{verifier.ErrTokenMissing, verifier.ErrInvalidSignature, verifier.ErrDPoPRequired} {
		wantStatus, wantHeaders, wantBody := resource.AuthErrorResponse(err)
		status, headers, body := resource.AuthErrorResponseWithMetadata(err, "")
		if headers["WWW-Authenticate"] != wantHeaders["WWW-Authenticate"] || status != wantStatus || body != wantBody {
			t.Errorf("AuthErrorResponseWithMetadata(%v, \"\") = (%d, %q, %q), want (%d, %q, %q)",
				err, status, headers["WWW-Authenticate"], body, wantStatus, wantHeaders["WWW-Authenticate"], wantBody)
		}
	}
}

// TestAuthErrorResponseWithMetadata_SanitizesCallerSuppliedValues: the
// construction-time gate in resource.New only covers values that arrive through
// WithResourceMetadataURL. This function is exported and the user guide routes
// custom middleware straight to it, so a deployment computing the URL per
// request — the multi-tenant case, where the tenant slug lands in the PRM path —
// reaches the emitter with a value nothing validated. A bare '"' would terminate
// the quoted-string and let the rest of the value append auth-params of its own.
func TestAuthErrorResponseWithMetadata_SanitizesCallerSuppliedValues(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		realm []string
		want  string
	}{
		{
			name: "quote in the metadata URL cannot close the parameter",
			url:  `https://as.example.com/prm", resource_metadata="https://evil.example.com/prm`,
			want: `Bearer error="invalid_token", resource_metadata="https://as.example.com/prm, resource_metadata=https://evil.example.com/prm"`,
		},
		{
			name: "backslash in the metadata URL cannot open a quoted-pair",
			url:  `https://as.example.com/a\"b`,
			want: `Bearer error="invalid_token", resource_metadata="https://as.example.com/ab"`,
		},
		{
			name:  "quote in the realm cannot close the parameter",
			url:   "https://as.example.com/prm",
			realm: []string{`api", error="insufficient_scope`},
			want:  `Bearer realm="api, error=insufficient_scope" error="invalid_token", resource_metadata="https://as.example.com/prm"`,
		},
		{
			name: "CR and LF cannot split the header",
			url:  "https://as.example.com/prm\r\nX-Injected: 1",
			want: `Bearer error="invalid_token", resource_metadata="https://as.example.com/prmX-Injected: 1"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, headers, _ := resource.AuthErrorResponseWithMetadata(verifier.ErrInvalidSignature, tt.url, tt.realm...)
			got := headers["WWW-Authenticate"]
			if got != tt.want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.want)
			}
			if strings.ContainsAny(got[len("Bearer "):], "\r\n") {
				t.Errorf("challenge carries a bare CR/LF: %q", got)
			}
		})
	}
}

// TestAuthErrorResponse_ScopeNamesReachTheChallengeNotTheBody records where the
// missing scopes went. RFC 6750 §3 defines `scope="..."` for exactly this, so
// the client still learns what to step up to; the enriched message naming the
// scopes the token *does* carry stays on the error.
func TestAuthErrorResponse_ScopeNamesReachTheChallengeNotTheBody(t *testing.T) {
	err := &resource.ScopeError{
		RequiredScopes: []string{"tools/admin", "tools/superuser"},
		Err:            fmt.Errorf(`%w: required scopes "tools/admin", "tools/superuser"; token has scopes: tools/add`, verifier.ErrInsufficientScope),
	}

	_, headers, body := resource.AuthErrorResponse(err)

	if want := `scope="tools/admin tools/superuser"`; !strings.Contains(headers["WWW-Authenticate"], want) {
		t.Errorf("WWW-Authenticate = %q, want it to contain %q", headers["WWW-Authenticate"], want)
	}
	if strings.Contains(body, "tools/add") {
		t.Errorf("body = %s, want it not to disclose the scopes the token carries", body)
	}
}

// TestAuthErrorResponseVerbose_RestoresTheErrorMessage covers the escape hatch,
// including that it changes nothing but the description.
func TestAuthErrorResponseVerbose_RestoresTheErrorMessage(t *testing.T) {
	err := fmt.Errorf("%w: no key for kid %q", verifier.ErrInvalidSignature, "2026-09-rotation-key")

	safeStatus, safeHeaders, safeBody := resource.AuthErrorResponse(err, "https://api.example.com")
	status, headers, body := resource.AuthErrorResponseVerbose(err, "https://api.example.com")

	if got := descriptionOf(t, body); got != err.Error() {
		t.Errorf("error_description = %q, want %q", got, err.Error())
	}
	if status != safeStatus {
		t.Errorf("status = %d, want %d", status, safeStatus)
	}
	if headers["WWW-Authenticate"] != safeHeaders["WWW-Authenticate"] {
		t.Errorf("WWW-Authenticate = %q, want %q", headers["WWW-Authenticate"], safeHeaders["WWW-Authenticate"])
	}
	if strings.Contains(safeBody, "2026-09-rotation-key") {
		t.Errorf("safe body = %s, want the verbose detail to stay out of it", safeBody)
	}
}

// TestAuthErrorResponse_NilErrorDoesNotPanic: a nil error is a programmer
// error, but the two entry points must agree on it rather than one returning a
// body and the other panicking on err.Error().
func TestAuthErrorResponse_NilErrorDoesNotPanic(t *testing.T) {
	for _, tt := range []struct {
		name string
		call func() (int, map[string]string, string)
	}{
		{"AuthErrorResponse", func() (int, map[string]string, string) { return resource.AuthErrorResponse(nil) }},
		{"AuthErrorResponseVerbose", func() (int, map[string]string, string) {
			return resource.AuthErrorResponseVerbose(nil)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on a nil error: %v", r)
				}
			}()
			if _, _, body := tt.call(); body == "" {
				t.Error("expected a body, got none")
			}
		})
	}
}
