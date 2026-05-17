package conformancetests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authplane/go-sdk/core/internal/oauth"
)

func TestRFC8693GrantTypeMustBeTokenExchange(t *testing.T) {
	Case(t, "rfc8693-grant-type-must-be-token-exchange")

	var receivedGrantType string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedGrantType = r.PostFormValue("grant_type")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged_token",
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}))
	defer ts.Close()

	_, err := testTokenExchange(context.Background(), ts.URL, "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "original_token",
	})
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if receivedGrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grant_type = %q, want token-exchange URN", receivedGrantType)
	}
}

func TestRFC8693SubjectTokenIsRequired(t *testing.T) {
	Case(t, "rfc8693-subject-token-is-required")

	_, err := testTokenExchange(context.Background(), "https://oauth.example.com/token", "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "", // empty
	})
	if err == nil {
		t.Fatal("expected error for empty subject_token")
	}
}

func TestRFC8693DefaultSubjectTokenTypeIsAccessToken(t *testing.T) {
	Case(t, "rfc8693-default-subject-token-type-is-access-token")

	var receivedSubjectTokenType string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedSubjectTokenType = r.PostFormValue("subject_token_type")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged_token",
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}))
	defer ts.Close()

	_, err := testTokenExchange(context.Background(), ts.URL, "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "original_token",
		// SubjectTokenType not set, should default
	})
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if receivedSubjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("subject_token_type = %q, want access_token type", receivedSubjectTokenType)
	}
}

func TestRFC8693ActorTokenTypeDefaultsWhenActorTokenIsPresent(t *testing.T) {
	Case(t, "rfc8693-actor-token-type-defaults-when-actor-token-is-present")

	var receivedActorTokenType string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedActorTokenType = r.PostFormValue("actor_token_type")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged_token",
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}))
	defer ts.Close()

	_, err := testTokenExchange(context.Background(), ts.URL, "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "original_token",
		ActorToken:   "actor_token",
		// ActorTokenType not set, should default
	})
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if receivedActorTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("actor_token_type = %q, want access_token type", receivedActorTokenType)
	}
}

func TestRFC8693ResourceParameterMustBeSentWhenConfigured(t *testing.T) {
	Case(t, "rfc8693-resource-parameter-must-be-sent-when-configured")

	var receivedResource string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedResource = r.PostFormValue("resource")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged_token",
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}))
	defer ts.Close()

	_, err := testTokenExchange(context.Background(), ts.URL, "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "original_token",
		Resources:    []string{"https://api.example.com"},
	})
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if receivedResource != "https://api.example.com" {
		t.Errorf("resource = %q, want %q", receivedResource, "https://api.example.com")
	}
}

func TestRFC8693MultipleResourceParametersMustBeEmitted(t *testing.T) {
	Case(t, "rfc8693-multiple-resource-parameters-must-be-emitted")

	var receivedResources []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedResources = r.PostForm["resource"]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged_token",
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}))
	defer ts.Close()

	_, err := testTokenExchange(context.Background(), ts.URL, "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "original_token",
		Resources:    []string{"https://api1.example.com", "https://api2.example.com"},
	})
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if len(receivedResources) != 2 {
		t.Fatalf("expected 2 resource params, got %d: %v", len(receivedResources), receivedResources)
	}
	if receivedResources[0] != "https://api1.example.com" || receivedResources[1] != "https://api2.example.com" {
		t.Errorf("resources = %v, want [https://api1.example.com, https://api2.example.com]", receivedResources)
	}
}

func TestRFC8693AudienceParameterMustBeSentWhenConfigured(t *testing.T) {
	Case(t, "rfc8693-audience-parameter-must-be-sent-when-configured")

	var receivedAudience string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedAudience = r.PostFormValue("audience")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged_token",
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}))
	defer ts.Close()

	_, err := testTokenExchange(context.Background(), ts.URL, "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "original_token",
		Audiences:    []string{"https://target.example.com"},
	})
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if receivedAudience != "https://target.example.com" {
		t.Errorf("audience = %q, want %q", receivedAudience, "https://target.example.com")
	}
}

func TestRFC8693MultipleAudienceParametersMustBeEmitted(t *testing.T) {
	Case(t, "rfc8693-multiple-audience-parameters-must-be-emitted")

	var receivedAudiences []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedAudiences = r.PostForm["audience"]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged_token",
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}))
	defer ts.Close()

	_, err := testTokenExchange(context.Background(), ts.URL, "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "original_token",
		Audiences:    []string{"https://target1.example.com", "https://target2.example.com"},
	})
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if len(receivedAudiences) != 2 {
		t.Fatalf("expected 2 audience params, got %d: %v", len(receivedAudiences), receivedAudiences)
	}
	if receivedAudiences[0] != "https://target1.example.com" || receivedAudiences[1] != "https://target2.example.com" {
		t.Errorf("audiences = %v, want [https://target1.example.com, https://target2.example.com]", receivedAudiences)
	}
}

func TestRFC8693EmptyResourceAndAudienceValuesMustBeOmitted(t *testing.T) {
	Case(t, "rfc8693-empty-resource-and-audience-values-must-be-omitted")

	var hasResource, hasAudience bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		_, hasResource = r.PostForm["resource"]
		_, hasAudience = r.PostForm["audience"]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged_token",
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}))
	defer ts.Close()

	_, err := testTokenExchange(context.Background(), ts.URL, "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "original_token",
		Resources:    nil,           // empty, should be omitted
		Audiences:    []string{" "}, // whitespace only, should be omitted
	})
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if hasResource {
		t.Error("empty resource should be omitted from form")
	}
	if hasAudience {
		t.Error("whitespace-only audience should be omitted from form")
	}
}

func TestRFC8693SuccessResponseMustUseAccessTokenIssuedTokenTypeWhenPresent(t *testing.T) {
	Case(t, "rfc8693-success-response-must-use-access-token-issued-token-type-when-present")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged_token",
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}))
	defer ts.Close()

	resp, err := testTokenExchange(context.Background(), ts.URL, "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "original_token",
	})
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if resp.IssuedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("issued_token_type = %q, want %q", resp.IssuedTokenType, "urn:ietf:params:oauth:token-type:access_token")
	}
}

func TestRFC8693ErrorMappingInvalidGrant(t *testing.T) {
	Case(t, "rfc8693-error-mapping-invalid-grant")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_grant",
			"error_description": "subject token is invalid",
		})
	}))
	defer ts.Close()

	_, err := testTokenExchange(context.Background(), ts.URL, "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "invalid_token",
	})
	if err == nil {
		t.Fatal("expected error for invalid_grant")
	}
	if !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant, got %v", err)
	}
}

func TestRFC8693TokenExchangeResponseMustContainIssuedTokenType(t *testing.T) {
	Case(t, "rfc8693-token-exchange-response-must-contain-issued-token-type")

	// Mock endpoint returns response WITHOUT issued_token_type.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "exchanged_token",
			"token_type":   "Bearer",
			// issued_token_type intentionally omitted
		})
	}))
	defer ts.Close()

	_, err := testTokenExchange(context.Background(), ts.URL, "test-client", "test-secret", oauth.TokenExchangeInput{
		SubjectToken: "original_token",
	})
	if err == nil {
		t.Fatal("expected error for missing issued_token_type")
	}
	if !errors.Is(err, oauth.ErrProtocolError) {
		t.Errorf("expected ErrProtocolError, got %v", err)
	}
	if !strings.Contains(err.Error(), "issued_token_type") {
		t.Errorf("error should mention issued_token_type: %v", err)
	}
}
