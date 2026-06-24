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

// TestNormalizeCnf pins the parser's confirmation-claim shape: a JSON
// object `cnf` is preserved and its `jkt` is surfaced as `cnf_jkt`;
// absent / null / non-object `cnf` collapses both fields to zero values
// so a malformed AS cannot pollute the typed shape downstream.
func TestNormalizeCnf(t *testing.T) {
	tests := []struct {
		name       string
		in         json.RawMessage
		wantCnf    json.RawMessage
		wantCnfJkt string
	}{
		{
			name:       "object_with_jkt_derives_thumbprint",
			in:         json.RawMessage(`{"jkt":"abc"}`),
			wantCnf:    json.RawMessage(`{"jkt":"abc"}`),
			wantCnfJkt: "abc",
		},
		{
			name:       "object_with_jkt_and_extension_member_preserves_both",
			in:         json.RawMessage(`{"jkt":"abc","x5t#S256":"hash"}`),
			wantCnf:    json.RawMessage(`{"jkt":"abc","x5t#S256":"hash"}`),
			wantCnfJkt: "abc",
		},
		{
			name:       "object_without_jkt_keeps_cnf_empties_jkt",
			in:         json.RawMessage(`{"x5t#S256":"hash"}`),
			wantCnf:    json.RawMessage(`{"x5t#S256":"hash"}`),
			wantCnfJkt: "",
		},
		{
			name:       "absent_cnf_collapses_to_zero",
			in:         nil,
			wantCnf:    nil,
			wantCnfJkt: "",
		},
		{
			name:       "null_cnf_drops_both",
			in:         json.RawMessage(`null`),
			wantCnf:    nil,
			wantCnfJkt: "",
		},
		{
			name:       "non_object_scalar_cnf_is_dropped",
			in:         json.RawMessage(`"not-an-object"`),
			wantCnf:    nil,
			wantCnfJkt: "",
		},
		{
			name:       "non_object_array_cnf_is_dropped",
			in:         json.RawMessage(`["a","b"]`),
			wantCnf:    nil,
			wantCnfJkt: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cnf := tt.in
			var cnfJkt string
			NormalizeCnf(&cnf, &cnfJkt)
			if string(cnf) != string(tt.wantCnf) {
				t.Errorf("Cnf: got %q, want %q", string(cnf), string(tt.wantCnf))
			}
			if cnfJkt != tt.wantCnfJkt {
				t.Errorf("CnfJkt: got %q, want %q", cnfJkt, tt.wantCnfJkt)
			}
		})
	}
}

// TestTokenResponse_ExpiresIn_WireTriState pins the round-trip semantics
// of the `*int64` `ExpiresIn` field so a cached response re-serializes to
// the exact shape the AS sent:
//
//   - missing on the wire → nil → omitted on re-marshal (omitempty).
//   - `"expires_in": 0` → non-nil zero → re-marshals as 0, NOT omitted.
//   - positive integer → round-trips verbatim.
//
// Locks the contract Set / cache callers rely on to distinguish a
// one-shot (RFC 6749 §5.1) token from an AS-omitted lifetime.
func TestTokenResponse_ExpiresIn_WireTriState(t *testing.T) {
	tests := []struct {
		name    string
		wire    string
		wantNil bool
		wantVal int64
		wantOut string
	}{
		{
			name:    "absent on wire decodes to nil and re-marshals as omitted",
			wire:    `{"access_token":"t","token_type":"Bearer"}`,
			wantNil: true,
			wantOut: `{"access_token":"t","token_type":"Bearer"}`,
		},
		{
			name:    "explicit zero decodes to non-nil zero and re-marshals as 0",
			wire:    `{"access_token":"t","token_type":"Bearer","expires_in":0}`,
			wantNil: false,
			wantVal: 0,
			wantOut: `{"access_token":"t","token_type":"Bearer","expires_in":0}`,
		},
		{
			name:    "positive value round-trips",
			wire:    `{"access_token":"t","token_type":"Bearer","expires_in":3600}`,
			wantNil: false,
			wantVal: 3600,
			wantOut: `{"access_token":"t","token_type":"Bearer","expires_in":3600}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TokenResponse
			if err := json.Unmarshal([]byte(tt.wire), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if tt.wantNil {
				if got.ExpiresIn != nil {
					t.Errorf("ExpiresIn: got %d, want nil", *got.ExpiresIn)
				}
			} else {
				if got.ExpiresIn == nil {
					t.Fatalf("ExpiresIn: got nil, want %d", tt.wantVal)
				}
				if *got.ExpiresIn != tt.wantVal {
					t.Errorf("ExpiresIn: got %d, want %d", *got.ExpiresIn, tt.wantVal)
				}
			}
			out, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(out) != tt.wantOut {
				t.Errorf("marshal: got %q, want %q", string(out), tt.wantOut)
			}
		})
	}
}
