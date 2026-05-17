package conformancetests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

func TestRFC8707ClientCredentialsResourceParameterShouldBeSupported(t *testing.T) {
	Case(t, "rfc8707-client-credentials-resource-parameter-should-be-supported")

	var receivedResource string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedResource = r.PostFormValue("resource")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	_, err := testClientCredentials(context.Background(), ts.URL, "test-client", "test-secret", []string{"read"}, []string{"https://api.example.com"})
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	if receivedResource != "https://api.example.com" {
		t.Errorf("resource = %q, want %q", receivedResource, "https://api.example.com")
	}
}

func TestRFC8707ClientCredentialsMultipleResourceParametersMustBeEmitted(t *testing.T) {
	Case(t, "rfc8707-client-credentials-multiple-resource-parameters-must-be-emitted")

	var receivedResources []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedResources = r.PostForm["resource"]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	_, err := testClientCredentials(context.Background(), ts.URL, "test-client", "test-secret",
		[]string{"read"}, []string{"https://api-one.example.com", "https://api-two.example.com"})
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}

	if len(receivedResources) != 2 {
		t.Fatalf("expected 2 resource parameters, got %d: %v", len(receivedResources), receivedResources)
	}
	if !slices.Contains(receivedResources, "https://api-one.example.com") {
		t.Errorf("missing resource https://api-one.example.com in %v", receivedResources)
	}
	if !slices.Contains(receivedResources, "https://api-two.example.com") {
		t.Errorf("missing resource https://api-two.example.com in %v", receivedResources)
	}
}

func TestRFC8707VerifierMustAcceptResourceWhenPresentInAudArray(t *testing.T) {
	Case(t, "rfc8707-verifier-must-accept-resource-when-present-in-aud-array")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://oauth.example.com", "https://api.example.com")

	// Token with audience as an array containing the resource.
	claims := testutil.StandardClaims("https://oauth.example.com", "https://api.example.com", "user123", "client456")
	claims["aud"] = []string{"https://api.example.com", "https://other.example.com"}
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	result, err := tv.VerifyToken(ctx, token, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !slices.Contains(result.Audience(), "https://api.example.com") {
		t.Error("expected api.example.com in audience")
	}
}
