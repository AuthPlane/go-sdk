package conformancetests

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/go-sdk/core/internal/oauth"
)

func TestRFC6749ClientCredentialsSuccessResponse(t *testing.T) {
	Case(t, "rfc6749-client-credentials-success-response")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new_token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	resp, err := testClientCredentials(context.Background(), ts.URL, "test-client", "test-secret", []string{"read"}, nil)
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	if resp.AccessToken != "new_token" {
		t.Errorf("access_token = %q, want %q", resp.AccessToken, "new_token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want %q", resp.TokenType, "Bearer")
	}
	if resp.ExpiresIn == nil || *resp.ExpiresIn != 3600 {
		got := "<nil>"
		if resp.ExpiresIn != nil {
			got = fmt.Sprintf("%d", *resp.ExpiresIn)
		}
		t.Errorf("expires_in = %s, want %d", got, 3600)
	}
}

func TestRFC6749BasicAuthCredentialsMustBeFormURLEncodedBeforeBase64(t *testing.T) {
	Case(t, "rfc6749-basic-auth-credentials-must-be-form-urlencoded-before-base64")

	var receivedAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
		})
	}))
	defer ts.Close()

	// Use special characters that need URL encoding.
	clientID := "client:with/special chars"
	clientSecret := "secret@with#special&chars"

	_, err := testClientCredentials(context.Background(), ts.URL, clientID, clientSecret, nil, nil)
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}

	// Verify the Authorization header is correctly form-encoded then base64-encoded.
	expected := "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(clientID)+":"+url.QueryEscape(clientSecret)))
	if receivedAuth != expected {
		t.Errorf("Authorization = %q, want %q", receivedAuth, expected)
	}
}

func TestRFC6749TokenResponseMustContainAccessToken(t *testing.T) {
	Case(t, "rfc6749-token-response-must-contain-access-token")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"token_type": "Bearer",
			"expires_in": 3600,
		})
	}))
	defer ts.Close()

	_, err := testClientCredentials(context.Background(), ts.URL, "test-client", "test-secret", nil, nil)
	if err == nil {
		t.Fatal("expected error when access_token is missing from response")
	}
	if !errors.Is(err, oauth.ErrProtocolError) {
		t.Errorf("expected ErrProtocolError, got: %v", err)
	}
}

func TestRFC6749TokenResponseTokenTypeMustBeSupported(t *testing.T) {
	Case(t, "rfc6749-token-response-token-type-must-be-supported")

	t.Run("bearer_accepted", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		}))
		defer ts.Close()

		resp, err := testClientCredentials(context.Background(), ts.URL, "test-client", "test-secret", nil, nil)
		if err != nil {
			t.Fatalf("client credentials: %v", err)
		}
		if resp.TokenType != "Bearer" {
			t.Errorf("token_type = %q, want %q", resp.TokenType, "Bearer")
		}
	})

	t.Run("missing_token_type_rejected", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok",
				"expires_in":   3600,
			})
		}))
		defer ts.Close()

		_, err := testClientCredentials(context.Background(), ts.URL, "test-client", "test-secret", nil, nil)
		if err == nil {
			t.Fatal("expected error when token_type is missing from response")
		}
	})

	t.Run("unsupported_token_type_rejected", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok",
				"token_type":   "N_A",
				"expires_in":   3600,
			})
		}))
		defer ts.Close()

		_, err := testClientCredentials(context.Background(), ts.URL, "test-client", "test-secret", nil, nil)
		if err == nil {
			t.Fatal("expected error when token_type is unsupported")
		}
		if !strings.Contains(err.Error(), "token_type") {
			t.Errorf("expected error mentioning token_type, got: %v", err)
		}
	})
}

func TestRFC6749TokenResponseExpiresInMustBeNonNegativeInteger(t *testing.T) {
	Case(t, "rfc6749-token-response-expires-in-must-be-non-negative-integer")

	// Server returns expires_in: -1 — the SDK must reject this as invalid.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   -1,
		})
	}))
	defer ts.Close()

	_, err := testClientCredentials(context.Background(), ts.URL, "test-client", "test-secret", nil, nil)
	if err == nil {
		t.Fatal("expected error when expires_in is negative (-1)")
	}
	errStr := strings.ToLower(err.Error())
	if !strings.Contains(errStr, "expires_in") && !strings.Contains(errStr, "non-negative") && !strings.Contains(errStr, "negative") {
		t.Logf("expires_in=-1 rejected with: %v", err)
	}
}

func TestRFC6749InvalidClientMustMapToAuthenticationFailure(t *testing.T) {
	Case(t, "rfc6749-invalid-client-must-map-to-authentication-failure")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_client",
			"error_description": "client authentication failed",
		})
	}))
	defer ts.Close()

	_, err := testClientCredentials(context.Background(), ts.URL, "bad-client", "bad-secret", nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid_client")
	}
	if !errors.Is(err, oauth.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient, got %v", err)
	}
}

func TestRFC6749ClientCredentialsScopesMustSupportMultipleValues(t *testing.T) {
	Case(t, "rfc6749-client-credentials-scopes-must-support-multiple-values")

	var receivedScope string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedScope = r.PostFormValue("scope")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	_, err := testClientCredentials(context.Background(), ts.URL, "test-client", "test-secret",
		[]string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}

	// Scope must be a single space-delimited string per RFC 6749.
	if receivedScope != "read write" {
		t.Errorf("scope = %q, want %q", receivedScope, "read write")
	}
}

func TestRFC9449TokenResponseTokenTypeDPoPMustBeAccepted(t *testing.T) {
	Case(t, "rfc9449-token-response-token-type-dpop-must-be-accepted")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "dpop_token",
			"token_type":   "DPoP",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	resp, err := testClientCredentials(context.Background(), ts.URL, "test-client", "test-secret", nil, nil)
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	if resp.TokenType != "DPoP" {
		t.Errorf("token_type = %q, want %q", resp.TokenType, "DPoP")
	}
	if resp.AccessToken != "dpop_token" {
		t.Errorf("access_token = %q, want %q", resp.AccessToken, "dpop_token")
	}
}
