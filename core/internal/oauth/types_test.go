package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestMapOAuthError_KnownCodes(t *testing.T) {
	tests := []struct {
		code string
		want error
	}{
		{"invalid_grant", ErrInvalidGrant},
		{"invalid_scope", ErrInvalidScope},
		{"invalid_client", ErrInvalidClient},
		{"unauthorized_client", ErrUnauthorizedClient},
		{"unsupported_grant_type", ErrUnsupportedGrantType},
		{"invalid_request", ErrInvalidRequest},
		{"server_error", ErrServerError},
		{"consent_required", ErrConsentRequired},
		{"interaction_required", ErrInteractionRequired},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := mapOAuthError(tt.code)
			if !errors.Is(got, tt.want) {
				t.Errorf("mapOAuthError(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

func TestMapOAuthError_UnknownCode(t *testing.T) {
	err := mapOAuthError("custom_error")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() != "auth: custom_error" {
		t.Errorf("expected 'auth: custom_error', got %q", err.Error())
	}
	// Should NOT match any known sentinel.
	if errors.Is(err, ErrInvalidGrant) {
		t.Error("unknown code should not match ErrInvalidGrant")
	}
}

func TestStringOrSlice_UnmarshalJSON_String(t *testing.T) {
	var s StringOrSlice
	if err := json.Unmarshal([]byte(`"single"`), &s); err != nil {
		t.Fatalf("unmarshal string: %v", err)
	}
	if len(s) != 1 || s[0] != "single" {
		t.Errorf("got %v, want [single]", s)
	}
}

func TestStringOrSlice_UnmarshalJSON_Array(t *testing.T) {
	var s StringOrSlice
	if err := json.Unmarshal([]byte(`["a","b"]`), &s); err != nil {
		t.Fatalf("unmarshal array: %v", err)
	}
	if len(s) != 2 || s[0] != "a" || s[1] != "b" {
		t.Errorf("got %v, want [a b]", s)
	}
}

func TestStringOrSlice_UnmarshalJSON_Invalid(t *testing.T) {
	var s StringOrSlice
	if err := json.Unmarshal([]byte(`123`), &s); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestConsentRequiredError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  ConsentRequiredError
		want string
	}{
		{
			name: "with description",
			err:  ConsentRequiredError{Description: "Authorize Google Calendar"},
			want: "auth: consent required: Authorize Google Calendar",
		},
		{
			name: "without description",
			err:  ConsentRequiredError{},
			want: "auth: consent required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConsentRequiredError_Unwrap(t *testing.T) {
	err := &ConsentRequiredError{
		ConsentURL:  "https://as.example.com/consent",
		Description: "Authorize access",
		Cause:       ErrConsentRequired,
	}
	if !errors.Is(err, ErrConsentRequired) {
		t.Error("expected errors.Is to match ErrConsentRequired via Unwrap")
	}
}

func TestConsentRequiredError_ErrorsAs(t *testing.T) {
	err := fmt.Errorf("token exchange failed: %w", &ConsentRequiredError{
		ConsentURL:  "https://as.example.com/consent",
		Description: "Authorize access",
		Cause:       ErrConsentRequired,
	})
	var consentErr *ConsentRequiredError
	if !errors.As(err, &consentErr) {
		t.Fatal("expected errors.As to match *ConsentRequiredError")
	}
	if consentErr.ConsentURL != "https://as.example.com/consent" {
		t.Errorf("ConsentURL = %q, want %q", consentErr.ConsentURL, "https://as.example.com/consent")
	}
}

func TestSentinelErrors_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrInvalidGrant, ErrInvalidScope, ErrInvalidClient,
		ErrUnauthorizedClient, ErrUnsupportedGrantType,
		ErrInvalidRequest, ErrServerError, ErrCircuitOpen,
		ErrConsentRequired, ErrInteractionRequired,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinels %d and %d should be distinct", i, j)
			}
		}
	}
}
