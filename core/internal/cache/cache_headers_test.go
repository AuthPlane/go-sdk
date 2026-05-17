package cache

import (
	"math"
	"net/http"
	"testing"
	"time"
)

func TestParseCacheExpiry_MaxAge(t *testing.T) {
	headers := http.Header{}
	headers.Set("Cache-Control", "max-age=300")
	expiry := ParseCacheExpiry(headers)
	if expiry.IsZero() {
		t.Fatal("expected non-zero expiry for max-age=300")
	}
	diff := time.Until(expiry).Seconds()
	if diff < 298 || diff > 302 {
		t.Errorf("expected ~300s, got %.1f", diff)
	}
}

func TestParseCacheExpiry_MaxAgeWithOtherDirectives(t *testing.T) {
	headers := http.Header{}
	headers.Set("Cache-Control", "public, max-age=600, must-revalidate")
	expiry := ParseCacheExpiry(headers)
	if expiry.IsZero() {
		t.Fatal("expected non-zero expiry")
	}
	diff := time.Until(expiry).Seconds()
	if diff < 598 || diff > 602 {
		t.Errorf("expected ~600s, got %.1f", diff)
	}
}

func TestParseCacheExpiry_NoCache(t *testing.T) {
	headers := http.Header{}
	headers.Set("Cache-Control", "no-cache")
	expiry := ParseCacheExpiry(headers)
	if !expiry.IsZero() {
		t.Errorf("expected zero expiry for no-cache, got %v", expiry)
	}
}

func TestParseCacheExpiry_NoStore(t *testing.T) {
	headers := http.Header{}
	headers.Set("Cache-Control", "no-store")
	expiry := ParseCacheExpiry(headers)
	if !expiry.IsZero() {
		t.Errorf("expected zero expiry for no-store, got %v", expiry)
	}
}

func TestParseCacheExpiry_ExpiresHeader(t *testing.T) {
	headers := http.Header{}
	future := time.Now().Add(1 * time.Hour).UTC().Format(http.TimeFormat)
	headers.Set("Expires", future)
	expiry := ParseCacheExpiry(headers)
	if expiry.IsZero() {
		t.Fatal("expected non-zero expiry from Expires header")
	}
	diff := time.Until(expiry).Seconds()
	if math.Abs(diff-3600) > 5 {
		t.Errorf("expected ~3600s, got %.1f", diff)
	}
}

func TestParseCacheExpiry_MaxAgeTakesPrecedenceOverExpires(t *testing.T) {
	headers := http.Header{}
	headers.Set("Cache-Control", "max-age=60")
	future := time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat)
	headers.Set("Expires", future)
	expiry := ParseCacheExpiry(headers)
	diff := time.Until(expiry).Seconds()
	if diff > 65 {
		t.Errorf("max-age should take precedence, expected ~60s, got %.1f", diff)
	}
}

func TestParseCacheExpiry_NoHeaders(t *testing.T) {
	headers := http.Header{}
	expiry := ParseCacheExpiry(headers)
	if !expiry.IsZero() {
		t.Errorf("expected zero expiry when no cache headers, got %v", expiry)
	}
}

func TestParseCacheExpiry_InvalidMaxAge(t *testing.T) {
	headers := http.Header{}
	headers.Set("Cache-Control", "max-age=not-a-number")
	expiry := ParseCacheExpiry(headers)
	if !expiry.IsZero() {
		t.Errorf("expected zero expiry for invalid max-age, got %v", expiry)
	}
}

func TestParseCacheExpiry_InvalidExpires(t *testing.T) {
	headers := http.Header{}
	headers.Set("Expires", "not-a-date")
	expiry := ParseCacheExpiry(headers)
	if !expiry.IsZero() {
		t.Errorf("expected zero expiry for invalid Expires, got %v", expiry)
	}
}

func TestParseCacheExpiry_MaxAgeZero(t *testing.T) {
	headers := http.Header{}
	headers.Set("Cache-Control", "max-age=0")
	expiry := ParseCacheExpiry(headers)
	if !expiry.IsZero() {
		t.Errorf("expected zero expiry for max-age=0, got %v", expiry)
	}
}

func TestParseMaxAge(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{"simple", "max-age=300", 300},
		{"with spaces", "max-age= 300 ", 300},
		{"mixed case", "Max-Age=600", 600},
		{"with other directives", "public, max-age=120, immutable", 120},
		{"missing", "public, no-transform", 0},
		{"negative", "max-age=-1", 0},
		{"not a number", "max-age=abc", 0},
		{"empty value", "max-age=", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMaxAge(tt.input)
			if got != tt.want {
				t.Errorf("parseMaxAge(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}
