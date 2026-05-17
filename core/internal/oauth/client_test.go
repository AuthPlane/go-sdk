package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/authplane/go-sdk/core/internal/ssrf"
)

func testFetchSettings() ssrf.FetchSettings {
	return ssrf.FetchSettings{
		SSRFProtection: false,
		AllowHTTP:      true,
		Timeout:        ssrf.DefaultTimeout,
	}
}

func testClientAuth() ClientAuthentication {
	return ClientAuthentication{
		Method:       ClientAuthClientSecretBasic,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestValidateClientAuthentication(t *testing.T) {
	if err := ValidateClientAuthentication(testClientAuth()); err != nil {
		t.Fatalf("expected valid auth, got %v", err)
	}

	err := ValidateClientAuthentication(ClientAuthentication{})
	if err == nil {
		t.Fatal("expected error for empty auth")
	}
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestClientCredentials_NoEndpoint(t *testing.T) {
	_, err := ClientCredentials(context.Background(), "", testClientAuth(), testFetchSettings(), nil, nil, nil)
	if err == nil {
		t.Fatal("expected error when token endpoint not configured")
	}
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestClientCredentials_ClientSecretBasic(t *testing.T) {
	var gotAuthHeader string
	var gotForm url.Values

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		gotForm = r.Form
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "new-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        r.FormValue("scope"),
		})
	}))
	defer srv.Close()

	resp, err := ClientCredentials(
		context.Background(),
		srv.URL,
		testClientAuth(),
		testFetchSettings(),
		[]string{"write", "read"},
		[]string{"https://api-1.example.com", "https://api-2.example.com"},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.AccessToken != "new-access-token" {
		t.Fatalf("unexpected access token %q", resp.AccessToken)
	}
	if gotAuthHeader == "" {
		t.Fatal("expected Authorization header")
	}
	if gotForm.Get("grant_type") != "client_credentials" {
		t.Fatalf("grant_type = %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("scope") != "read write" {
		t.Fatalf("scope = %q, want %q", gotForm.Get("scope"), "read write")
	}
	if resources := gotForm["resource"]; len(resources) != 2 {
		t.Fatalf("resource params = %v, want 2 entries", resources)
	}
}

func TestClientCredentials_ClientSecretPost(t *testing.T) {
	var gotAuthHeader string
	var gotForm url.Values

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		gotForm = r.Form
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "post-token",
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	auth := ClientAuthentication{
		Method:       ClientAuthClientSecretPost,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}
	_, err := ClientCredentials(context.Background(), srv.URL, auth, testFetchSettings(), nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuthHeader != "" {
		t.Fatalf("unexpected Authorization header %q", gotAuthHeader)
	}
	if gotForm.Get("client_id") != "client-id" {
		t.Fatalf("client_id = %q", gotForm.Get("client_id"))
	}
	if gotForm.Get("client_secret") != "client-secret" {
		t.Fatalf("client_secret = %q", gotForm.Get("client_secret"))
	}
}

func TestClientCredentials_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_scope",
			"error_description": "The requested scope is invalid",
		})
	}))
	defer srv.Close()

	_, err := ClientCredentials(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), []string{"bad-scope"}, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("expected ErrInvalidScope, got %v", err)
	}
}

func TestTokenExchange_Success(t *testing.T) {
	var gotForm url.Values

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		gotForm = r.Form
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":      "exchanged-token",
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}))
	defer srv.Close()

	resp, err := TokenExchange(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), TokenExchangeInput{
		SubjectToken: "subject-token",
		Scopes:       []string{"write", "read"},
		Resources:    []string{"https://api.example.com"},
		Audiences:    []string{"https://target.example.com"},
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "exchanged-token" {
		t.Fatalf("unexpected access token %q", resp.AccessToken)
	}
	if gotForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Fatalf("grant_type = %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token" {
		t.Fatalf("subject_token_type = %q", gotForm.Get("subject_token_type"))
	}
	if gotForm.Get("scope") != "read write" {
		t.Fatalf("scope = %q", gotForm.Get("scope"))
	}
	if gotForm.Get("resource") != "https://api.example.com" {
		t.Fatalf("resource = %q", gotForm.Get("resource"))
	}
	if gotForm.Get("audience") != "https://target.example.com" {
		t.Fatalf("audience = %q", gotForm.Get("audience"))
	}
}

func TestTokenExchange_SubjectTokenRequired(t *testing.T) {
	_, err := TokenExchange(context.Background(), "https://oauth.example.com/token", testClientAuth(), testFetchSettings(), TokenExchangeInput{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestIntrospect_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"active":    true,
			"client_id": "client-id",
			"custom":    "value",
		})
	}))
	defer srv.Close()

	resp, err := Introspect(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), "some-token", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected active response")
	}
	if resp.Extra["custom"] != "value" {
		t.Fatalf("unexpected extra claims: %#v", resp.Extra)
	}
}

func TestRevoke_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := Revoke(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), "some-token", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- DPoP provider mock and tests ---

type mockDPoPProvider struct {
	buildCalls []struct{ method, url string }
	noteNonces []struct{ url, nonce string }
	headers    map[string]string
	buildErr   error
}

func (m *mockDPoPProvider) BuildHeaders(method, url string) (map[string]string, error) {
	m.buildCalls = append(m.buildCalls, struct{ method, url string }{method, url})
	if m.buildErr != nil {
		return nil, m.buildErr
	}
	return m.headers, nil
}

func (m *mockDPoPProvider) NoteNonce(url, nonce string) {
	m.noteNonces = append(m.noteNonces, struct{ url, nonce string }{url, nonce})
}

func TestPostForm_AttachesDPoPHeader(t *testing.T) {
	var gotDPoP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDPoP = r.Header.Get("DPoP")
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "tok",
			"token_type":   "DPoP",
		})
	}))
	defer srv.Close()

	dp := &mockDPoPProvider{
		headers: map[string]string{"DPoP": "proof-jwt"},
	}
	_, err := ClientCredentials(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), nil, nil, dp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotDPoP != "proof-jwt" {
		t.Fatalf("DPoP header = %q, want %q", gotDPoP, "proof-jwt")
	}
	if len(dp.buildCalls) != 1 {
		t.Fatalf("BuildHeaders called %d times, want 1", len(dp.buildCalls))
	}
	if dp.buildCalls[0].method != "POST" {
		t.Fatalf("BuildHeaders method = %q, want POST", dp.buildCalls[0].method)
	}
}

func TestDPoPGrant_RejectsBearerTokenType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer", // Wrong: should be DPoP when DPoP was used
		})
	}))
	defer srv.Close()

	dp := &mockDPoPProvider{
		headers: map[string]string{"DPoP": "proof-jwt"},
	}
	_, err := ClientCredentials(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), nil, nil, dp)
	if err == nil {
		t.Fatal("expected error when DPoP grant returns token_type Bearer")
	}
	if !errors.Is(err, ErrProtocolError) {
		t.Fatalf("expected ErrProtocolError, got %v", err)
	}
}

func TestDPoPGrant_AcceptsDPoPTokenType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "tok",
			"token_type":   "DPoP",
		})
	}))
	defer srv.Close()

	dp := &mockDPoPProvider{
		headers: map[string]string{"DPoP": "proof-jwt"},
	}
	resp, err := ClientCredentials(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), nil, nil, dp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.TokenType != "DPoP" {
		t.Errorf("token_type = %q, want DPoP", resp.TokenType)
	}
}

func TestDPoPGrant_AcceptsDPoPTokenTypeCaseInsensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "tok",
			"token_type":   "dpop", // lowercase
		})
	}))
	defer srv.Close()

	dp := &mockDPoPProvider{
		headers: map[string]string{"DPoP": "proof-jwt"},
	}
	_, err := ClientCredentials(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), nil, nil, dp)
	if err != nil {
		t.Fatalf("expected case-insensitive DPoP token_type to be accepted: %v", err)
	}
}

func TestPostForm_NilProviderSkipsDPoP(t *testing.T) {
	var gotDPoP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDPoP = r.Header.Get("DPoP")
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	_, err := ClientCredentials(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotDPoP != "" {
		t.Fatalf("DPoP header = %q, want empty", gotDPoP)
	}
}

func TestPostForm_NonceRetryOnUseDPoPNonce(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("DPoP-Nonce", "server-nonce-1")
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "use_dpop_nonce",
			})
			return
		}
		w.Header().Set("DPoP-Nonce", "server-nonce-2")
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "tok",
			"token_type":   "DPoP",
		})
	}))
	defer srv.Close()

	dp := &mockDPoPProvider{
		headers: map[string]string{"DPoP": "proof-jwt"},
	}
	resp, err := ClientCredentials(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), nil, nil, dp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "tok" {
		t.Fatalf("access_token = %q, want %q", resp.AccessToken, "tok")
	}
	if callCount != 2 {
		t.Fatalf("HTTP calls = %d, want 2", callCount)
	}
	if len(dp.buildCalls) != 2 {
		t.Fatalf("BuildHeaders called %d times, want 2", len(dp.buildCalls))
	}
	// Both nonces should be stored.
	if len(dp.noteNonces) != 2 {
		t.Fatalf("NoteNonce called %d times, want 2", len(dp.noteNonces))
	}
	if dp.noteNonces[0].nonce != "server-nonce-1" {
		t.Fatalf("first nonce = %q, want %q", dp.noteNonces[0].nonce, "server-nonce-1")
	}
	if dp.noteNonces[1].nonce != "server-nonce-2" {
		t.Fatalf("second nonce = %q, want %q", dp.noteNonces[1].nonce, "server-nonce-2")
	}
}

func TestPostForm_StoresNonceFromSuccessResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", "fresh-nonce")
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "tok",
			"token_type":   "DPoP",
		})
	}))
	defer srv.Close()

	dp := &mockDPoPProvider{
		headers: map[string]string{"DPoP": "proof-jwt"},
	}
	_, err := ClientCredentials(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), nil, nil, dp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dp.noteNonces) != 1 {
		t.Fatalf("NoteNonce called %d times, want 1", len(dp.noteNonces))
	}
	if dp.noteNonces[0].nonce != "fresh-nonce" {
		t.Fatalf("nonce = %q, want %q", dp.noteNonces[0].nonce, "fresh-nonce")
	}
}

func TestPostForm_NoRetryWithoutNonce(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Return use_dpop_nonce error but WITHOUT DPoP-Nonce header.
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "use_dpop_nonce",
		})
	}))
	defer srv.Close()

	dp := &mockDPoPProvider{
		headers: map[string]string{"DPoP": "proof-jwt"},
	}
	_, err := ClientCredentials(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), nil, nil, dp)
	if err == nil {
		t.Fatal("expected error")
	}
	if callCount != 1 {
		t.Fatalf("HTTP calls = %d, want 1 (no retry without nonce header)", callCount)
	}
}

func TestTokenExchange_ConsentRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "consent_required",
			"error_description": "Authorize access to Google Calendar",
			"consent_url":       "https://as.example.com/vault/consent/google-calendar",
		})
	}))
	defer srv.Close()

	_, err := TokenExchange(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), TokenExchangeInput{
		SubjectToken: "subject-token",
	}, nil)
	if err == nil {
		t.Fatal("expected error")
	}

	var consentErr *ConsentRequiredError
	if !errors.As(err, &consentErr) {
		t.Fatalf("expected *ConsentRequiredError, got %T: %v", err, err)
	}
	if consentErr.ConsentURL != "https://as.example.com/vault/consent/google-calendar" {
		t.Errorf("ConsentURL = %q", consentErr.ConsentURL)
	}
	if consentErr.Description != "Authorize access to Google Calendar" {
		t.Errorf("Description = %q", consentErr.Description)
	}
	if !errors.Is(consentErr, ErrConsentRequired) {
		t.Error("expected Cause to be ErrConsentRequired")
	}
}

func TestTokenExchange_InteractionRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "interaction_required",
			"error_description": "User interaction needed",
		})
	}))
	defer srv.Close()

	_, err := TokenExchange(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), TokenExchangeInput{
		SubjectToken: "subject-token",
	}, nil)
	if err == nil {
		t.Fatal("expected error")
	}

	var consentErr *ConsentRequiredError
	if !errors.As(err, &consentErr) {
		t.Fatalf("expected *ConsentRequiredError, got %T: %v", err, err)
	}
	if consentErr.ConsentURL != "" {
		t.Errorf("ConsentURL should be empty when AS omits it, got %q", consentErr.ConsentURL)
	}
	if !errors.Is(consentErr, ErrInteractionRequired) {
		t.Error("expected Cause to be ErrInteractionRequired")
	}
}

func TestTokenExchange_ConsentRequiredWithoutConsentURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "consent_required",
			"error_description": "Consent needed",
		})
	}))
	defer srv.Close()

	_, err := TokenExchange(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), TokenExchangeInput{
		SubjectToken: "subject-token",
	}, nil)

	var consentErr *ConsentRequiredError
	if !errors.As(err, &consentErr) {
		t.Fatalf("expected *ConsentRequiredError, got %T: %v", err, err)
	}
	if consentErr.ConsentURL != "" {
		t.Errorf("ConsentURL should be empty, got %q", consentErr.ConsentURL)
	}
	if consentErr.Description != "Consent needed" {
		t.Errorf("Description = %q", consentErr.Description)
	}
}

func TestTokenExchange_MissingIssuedTokenType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
			// issued_token_type intentionally omitted
		})
	}))
	defer srv.Close()

	_, err := TokenExchange(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), TokenExchangeInput{
		SubjectToken: "subject-token",
	}, nil)
	if err == nil {
		t.Fatal("expected error for missing issued_token_type")
	}
	if !errors.Is(err, ErrProtocolError) {
		t.Errorf("expected ErrProtocolError, got %v", err)
	}
}

func TestPostForm_BuildHeadersErrorAbortsRequest(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	dp := &mockDPoPProvider{
		buildErr: errors.New("key generation failed"),
	}
	_, err := ClientCredentials(context.Background(), srv.URL, testClientAuth(), testFetchSettings(), nil, nil, dp)
	if err == nil {
		t.Fatal("expected error")
	}
	if callCount != 0 {
		t.Fatalf("HTTP calls = %d, want 0 (BuildHeaders error should abort)", callCount)
	}
}
