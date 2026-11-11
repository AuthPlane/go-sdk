package verifier

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrTokenMissing, ErrTokenExpired, ErrInvalidSignature,
		ErrInvalidClaims, ErrIssuerMismatch, ErrAudienceMismatch,
		ErrInsufficientScope, ErrTokenRevoked, ErrJWKSUnavailable,
		ErrDPoPRequired, ErrDPoPInvalid,
		ErrDPoPKeyMismatch, ErrDPoPReplayDetected,
		ErrDPoPNotSupported,
		ErrMetadataUnavailable,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinels %d and %d should be distinct: %v == %v", i, j, a, b)
			}
		}
	}
}

func TestSentinelErrors_WrappingPreservesIdentity(t *testing.T) {
	wrapped := fmt.Errorf("context: %w", ErrTokenExpired)
	if !errors.Is(wrapped, ErrTokenExpired) {
		t.Error("wrapped error should match ErrTokenExpired")
	}
}

func TestSentinelErrors_DoubleWrapping(t *testing.T) {
	inner := fmt.Errorf("inner: %w", ErrInsufficientScope)
	outer := fmt.Errorf("outer: %w", inner)
	if !errors.Is(outer, ErrInsufficientScope) {
		t.Error("double-wrapped error should match ErrInsufficientScope")
	}
}
