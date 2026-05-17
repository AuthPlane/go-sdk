package conformancetests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRFC7009Revocation200IsSuccessEvenForAlreadyInvalidToken(t *testing.T) {
	Case(t, "rfc7009-revocation-200-is-success-even-for-already-invalid-token")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 OK with empty body (already revoked token).
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	err := testRevoke(context.Background(), ts.URL, "test-client", "test-secret", "already-revoked-token")
	if err != nil {
		t.Fatalf("revoke should succeed for already-invalid token: %v", err)
	}
}

func TestRFC7009RevocationRequestMustPostTokenAndTokenTypeHint(t *testing.T) {
	Case(t, "rfc7009-revocation-request-must-post-token-and-token-type-hint")

	var (
		receivedMethod string
		receivedToken  string
		receivedHint   string
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		r.ParseForm()
		receivedToken = r.PostFormValue("token")
		receivedHint = r.PostFormValue("token_type_hint")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	err := testRevoke(context.Background(), ts.URL, "test-client", "test-secret", "my-token")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if receivedMethod != "POST" {
		t.Errorf("method = %q, want POST", receivedMethod)
	}
	if receivedToken != "my-token" {
		t.Errorf("token = %q, want %q", receivedToken, "my-token")
	}
	if receivedHint != "access_token" {
		t.Errorf("token_type_hint = %q, want %q", receivedHint, "access_token")
	}
}

func TestRFC7009RevocationServerErrorsMustSurface(t *testing.T) {
	Case(t, "rfc7009-revocation-server-errors-must-surface")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "server_error",
			"error_description": "internal failure",
		})
	}))
	defer ts.Close()

	err := testRevoke(context.Background(), ts.URL, "test-client", "test-secret", "some-token")
	if err == nil {
		t.Fatal("expected error for server error")
	}
}
