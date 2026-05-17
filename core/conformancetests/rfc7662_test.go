package conformancetests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

func TestRFC7662IntrospectionRequestMustPostTokenAndAccessTokenHint(t *testing.T) {
	Case(t, "rfc7662-introspection-request-must-post-token-and-access-token-hint")

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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"active": true})
	}))
	defer ts.Close()

	_, err := testIntrospect(context.Background(), ts.URL, "test-client", "test-secret", "my-token")
	if err != nil {
		t.Fatalf("introspect: %v", err)
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

func TestRFC7662IntrospectionWithoutCredentialsMustNotSendAuthorizationHeader(t *testing.T) {
	Case(t, "rfc7662-introspection-without-credentials-must-not-send-authorization-header",
		Partial("credentials-always-sent",
			"Go SDK auth client always sends Basic auth; there is no credentialless introspection mode"))

	// The Go SDK always requires client_id and client_secret to create an AuthClient,
	// and always sends the Authorization header. This is a design decision.
	var receivedAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"active": true})
	}))
	defer ts.Close()

	_, err := testIntrospect(context.Background(), ts.URL, "test-client", "test-secret", "tok")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	// Confirm auth header is sent (partial coverage: SDK always sends credentials).
	if receivedAuth == "" {
		t.Error("expected Authorization header to be sent")
	}
}

func TestRFC7662IntrospectionBasicAuthMustBeSupported(t *testing.T) {
	Case(t, "rfc7662-introspection-basic-auth-must-be-supported")

	var receivedAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"active": true})
	}))
	defer ts.Close()

	_, err := testIntrospect(context.Background(), ts.URL, "test-client", "test-secret", "tok")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if len(receivedAuth) < 6 || receivedAuth[:6] != "Basic " {
		t.Errorf("Authorization = %q, expected Basic auth", receivedAuth)
	}
}

func TestRFC7662IntrospectionActiveFalseMustParseAsInactive(t *testing.T) {
	Case(t, "rfc7662-introspection-active-false-must-parse-as-inactive")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"active": false})
	}))
	defer ts.Close()

	resp, err := testIntrospect(context.Background(), ts.URL, "test-client", "test-secret", "tok")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if resp.Active {
		t.Error("expected Active=false")
	}
}

func TestRFC7662IntrospectionMissingActiveMustDefaultToInactive(t *testing.T) {
	Case(t, "rfc7662-introspection-missing-active-must-default-to-inactive")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Response without "active" field — per catalog: introspection_response: { error: "invalid_token" }.
		json.NewEncoder(w).Encode(map[string]any{"error": "invalid_token"})
	}))
	defer ts.Close()

	resp, err := testIntrospect(context.Background(), ts.URL, "test-client", "test-secret", "tok")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	// When "active" is missing, Go's JSON unmarshaling defaults bool to false.
	if resp.Active {
		t.Error("expected Active=false when field is missing")
	}
}

func TestRFC7662IntrospectionStandardFieldsMustRoundTrip(t *testing.T) {
	Case(t, "rfc7662-introspection-standard-fields-must-round-trip")

	now := time.Now().Unix()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active":     true,
			"scope":      "read write",
			"client_id":  "client456",
			"username":   "user123",
			"token_type": "Bearer",
			"iss":        "https://oauth.example.com",
			"sub":        "user123",
			"aud":        "https://api.example.com",
			"exp":        now + 3600,
			"iat":        now,
			"jti":        "unique-jti",
			"custom":     "extra_value",
		})
	}))
	defer ts.Close()

	resp, err := testIntrospect(context.Background(), ts.URL, "test-client", "test-secret", "tok")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if !resp.Active {
		t.Error("expected Active=true")
	}
	if resp.Scope != "read write" {
		t.Errorf("scope = %q, want %q", resp.Scope, "read write")
	}
	if resp.ClientID != "client456" {
		t.Errorf("client_id = %q, want %q", resp.ClientID, "client456")
	}
	if resp.Username != "user123" {
		t.Errorf("username = %q, want %q", resp.Username, "user123")
	}
	if resp.Subject != "user123" {
		t.Errorf("sub = %q, want %q", resp.Subject, "user123")
	}
	if resp.Issuer != "https://oauth.example.com" {
		t.Errorf("iss = %q, want %q", resp.Issuer, "https://oauth.example.com")
	}
	if resp.JTI != "unique-jti" {
		t.Errorf("jti = %q, want %q", resp.JTI, "unique-jti")
	}
	if len(resp.Audience) != 1 || resp.Audience[0] != "https://api.example.com" {
		t.Errorf("aud = %v, want [\"https://api.example.com\"]", resp.Audience)
	}
	// Extra fields should be captured.
	if resp.Extra == nil || resp.Extra["custom"] != "extra_value" {
		t.Errorf("extra custom field not captured: %v", resp.Extra)
	}
}

func TestRFC7662IntrospectionAudienceMustParseStringOrArray(t *testing.T) {
	Case(t, "rfc7662-introspection-audience-must-parse-string-or-array")

	t.Run("string_aud", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"aud":    "https://api.example.com",
			})
		}))
		defer ts.Close()

		resp, err := testIntrospect(context.Background(), ts.URL, "test-client", "test-secret", "tok")
		if err != nil {
			t.Fatalf("introspect: %v", err)
		}
		if len(resp.Audience) != 1 || resp.Audience[0] != "https://api.example.com" {
			t.Errorf("aud = %v, want [\"https://api.example.com\"]", resp.Audience)
		}
	})

	t.Run("array_aud", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"aud":    []string{"https://api.example.com", "https://other.example.com"},
			})
		}))
		defer ts.Close()

		resp, err := testIntrospect(context.Background(), ts.URL, "test-client", "test-secret", "tok")
		if err != nil {
			t.Fatalf("introspect: %v", err)
		}
		if len(resp.Audience) != 2 {
			t.Errorf("aud = %v, want 2 elements", resp.Audience)
		}
	})
}

func TestRFC7662VerifierActiveFalseMustRejectToken(t *testing.T) {
	Case(t, "rfc7662-verifier-active-false-must-reject-token")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Verifier with a revocation checker that reports the token as revoked.
	tv, _ := newTestVerifier(t, key, "key-0", "https://oauth.example.com", "https://api.example.com",
		verifier.WithRevocationChecker(func(ctx context.Context, claims *verifier.VerifiedClaims, rawToken string) (bool, error) {
			return true, nil // always revoked
		}))

	claims := testutil.StandardClaims("https://oauth.example.com", "https://api.example.com", "user123", "client456")
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error for revoked token")
	}
	if !errors.Is(err, verifier.ErrTokenRevoked) {
		t.Errorf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestRFC7662IntrospectionFailOpenPolicyMustBeExplicitlyTested(t *testing.T) {
	Case(t, "rfc7662-introspection-fail-open-policy-must-be-explicitly-tested")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Default fail-open: revocation checker returns an error, token should still be accepted.
	tvOpen, _ := newTestVerifier(t, key, "key-0", "https://oauth.example.com", "https://api.example.com",
		verifier.WithRevocationChecker(func(ctx context.Context, claims *verifier.VerifiedClaims, rawToken string) (bool, error) {
			return false, errors.New("revocation check unavailable")
		}))

	claims := testutil.StandardClaims("https://oauth.example.com", "https://api.example.com", "user123", "client456")
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	result, err := tvOpen.VerifyToken(ctx, token, nil)
	if err != nil {
		t.Fatalf("fail-open should accept token: %v", err)
	}
	if result.Sub() != "user123" {
		t.Errorf("sub = %q, want %q", result.Sub(), "user123")
	}

	// Fail-closed: revocation checker returns an error, token should be rejected.
	tvClosed, _ := newTestVerifier(t, key, "key-0", "https://oauth.example.com", "https://api.example.com",
		verifier.WithRevocationChecker(func(ctx context.Context, claims *verifier.VerifiedClaims, rawToken string) (bool, error) {
			return false, errors.New("revocation check unavailable")
		}),
		verifier.WithFailClosed())

	_, err = tvClosed.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("fail-closed should reject token when revocation check fails")
	}
	if !errors.Is(err, verifier.ErrTokenRevoked) {
		t.Errorf("expected ErrTokenRevoked, got %v", err)
	}
}
