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
		ErrSSRFBlocked, ErrDPoPRequired, ErrDPoPInvalid,
		ErrDPoPKeyMismatch, ErrDPoPReplayDetected,
		ErrDPoPNotSupported,
		ErrMetadataUnavailable, ErrProtocolError,
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

func TestStringOrSlice_UnmarshalString(t *testing.T) {
	var s StringOrSlice
	if err := s.UnmarshalJSON([]byte(`"single"`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) != 1 || s[0] != "single" {
		t.Errorf("expected [single], got %v", s)
	}
}

func TestStringOrSlice_UnmarshalArray(t *testing.T) {
	var s StringOrSlice
	if err := s.UnmarshalJSON([]byte(`["a","b"]`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) != 2 || s[0] != "a" || s[1] != "b" {
		t.Errorf("expected [a b], got %v", s)
	}
}

func TestStringOrSlice_UnmarshalInvalid(t *testing.T) {
	var s StringOrSlice
	if err := s.UnmarshalJSON([]byte(`123`)); err == nil {
		t.Error("expected error for non-string, non-array")
	}
}

func TestStringOrSlice_MarshalSingle(t *testing.T) {
	s := StringOrSlice{"only"}
	data, err := s.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != `"only"` {
		t.Errorf("expected \"only\", got %s", data)
	}
}

func TestStringOrSlice_MarshalMultiple(t *testing.T) {
	s := StringOrSlice{"a", "b"}
	data, err := s.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != `["a","b"]` {
		t.Errorf("expected [\"a\",\"b\"], got %s", data)
	}
}
