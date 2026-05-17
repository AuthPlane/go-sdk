package authplane

import (
	"errors"
	"fmt"
	"testing"

	"github.com/authplane/go-sdk/core/internal/oauth"
	"github.com/authplane/go-sdk/core/internal/ssrf"
)

func TestShouldTripCircuitBreaker(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantTrip bool
	}{
		// Infrastructure failures — should trip.
		{"server_error", oauth.ErrServerError, true},
		{"protocol_error", oauth.ErrProtocolError, true},
		{"network error", errors.New("dial tcp: connection refused"), true},
		{"unknown error", errors.New("something unexpected"), true},

		// Permanent misconfiguration — should trip.
		{"invalid_client", oauth.ErrInvalidClient, true},
		{"unauthorized_client", oauth.ErrUnauthorizedClient, true},

		// User-fixable errors — should NOT trip.
		{"consent_required sentinel", oauth.ErrConsentRequired, false},
		{"interaction_required sentinel", oauth.ErrInteractionRequired, false},
		{"ConsentRequiredError struct", &oauth.ConsentRequiredError{
			ConsentURL:  "https://as.example.com/vault/connect/github",
			Description: "user must grant access",
			Cause:       oauth.ErrConsentRequired,
		}, false},
		{"ConsentRequiredError without URL", &oauth.ConsentRequiredError{
			Cause: oauth.ErrConsentRequired,
		}, false},

		// Per-request errors — should NOT trip.
		{"invalid_grant", oauth.ErrInvalidGrant, false},
		{"invalid_scope", oauth.ErrInvalidScope, false},
		{"use_dpop_nonce", oauth.ErrUseDPoPNonce, false},

		// SSRF — should NOT trip.
		{"ssrf_blocked", ssrf.ErrSSRFBlocked, false},

		// Wrapped errors — classification should survive wrapping.
		{"wrapped server_error", fmt.Errorf("exchange: %w", oauth.ErrServerError), true},
		{"wrapped consent_required", fmt.Errorf("exchange: %w", oauth.ErrConsentRequired), false},
		{"wrapped invalid_client", fmt.Errorf("exchange: %w", oauth.ErrInvalidClient), true},
		{"wrapped ConsentRequiredError", fmt.Errorf("exchange: %w", &oauth.ConsentRequiredError{
			ConsentURL: "https://as.example.com/consent",
			Cause:      oauth.ErrConsentRequired,
		}), false},
		{"wrapped ssrf", fmt.Errorf("metadata: %w", ssrf.ErrSSRFBlocked), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldTripCircuitBreaker(tt.err)
			if got != tt.wantTrip {
				t.Errorf("shouldTripCircuitBreaker(%v) = %v, want %v", tt.err, got, tt.wantTrip)
			}
		})
	}
}
