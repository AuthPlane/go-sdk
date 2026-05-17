package testutil

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestGenerateES256Key(t *testing.T) {
	key, err := GenerateES256Key()
	if err != nil {
		t.Fatalf("failed to generate ES256 key: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestGenerateRS256Key(t *testing.T) {
	key, err := GenerateRS256Key()
	if err != nil {
		t.Fatalf("failed to generate RS256 key: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestBuildJWKS_ES256(t *testing.T) {
	key, _ := GenerateES256Key()
	data, err := BuildJWKS(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to build JWKS: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty JWKS")
	}
}

func TestBuildJWKS_RS256(t *testing.T) {
	key, _ := GenerateRS256Key()
	data, err := BuildJWKS(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to build JWKS: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty JWKS")
	}
}

func TestBuildJWKSWithKID(t *testing.T) {
	key, _ := GenerateES256Key()
	data, err := BuildJWKSWithKID(&key.PublicKey, "my-kid")
	if err != nil {
		t.Fatalf("failed to build JWKS: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty JWKS")
	}
}

func TestSignToken_ES256_RoundTrip(t *testing.T) {
	key, _ := GenerateES256Key()
	claims := StandardClaims("https://issuer.example.com", "https://api.example.com", "user-1", "client-1")
	token, err := SignToken(claims, key, jose.ES256, "test-kid")
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// Parse and verify claims
	parsed, err := ParseSignedToken(token)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if parsed["iss"] != "https://issuer.example.com" {
		t.Errorf("expected issuer 'https://issuer.example.com', got %v", parsed["iss"])
	}
	if parsed["sub"] != "user-1" {
		t.Errorf("expected sub 'user-1', got %v", parsed["sub"])
	}
}

func TestSignToken_RS256_RoundTrip(t *testing.T) {
	key, _ := GenerateRS256Key()
	claims := StandardClaims("https://issuer.example.com", "https://api.example.com", "user-1", "client-1")
	token, err := SignToken(claims, key, jose.RS256, "rsa-kid")
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	parsed, err := ParseSignedToken(token)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if parsed["iss"] != "https://issuer.example.com" {
		t.Errorf("unexpected issuer: %v", parsed["iss"])
	}
}

func TestSignTokenWithClaims_ExtraClaims(t *testing.T) {
	key, _ := GenerateES256Key()
	extra := map[string]any{
		"scope":  "read write",
		"custom": "value",
	}
	token, err := SignTokenWithClaims(key, jose.ES256, "kid", "https://iss.example.com", "https://aud.example.com", "sub", "client", extra)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	parsed, err := ParseSignedToken(token)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed["scope"] != "read write" {
		t.Errorf("expected scope 'read write', got %v", parsed["scope"])
	}
	if parsed["custom"] != "value" {
		t.Errorf("expected custom 'value', got %v", parsed["custom"])
	}
}

func TestMockASMetadata(t *testing.T) {
	data := MockASMetadata("https://auth.example.com", "https://auth.example.com/jwks")
	if len(data) == 0 {
		t.Fatal("expected non-empty metadata")
	}
}

func TestStandardClaims(t *testing.T) {
	claims := StandardClaims("iss", "aud", "sub", "client")
	if claims["iss"] != "iss" {
		t.Errorf("unexpected iss: %v", claims["iss"])
	}
	if claims["aud"] != "aud" {
		t.Errorf("unexpected aud: %v", claims["aud"])
	}
	if claims["sub"] != "sub" {
		t.Errorf("unexpected sub: %v", claims["sub"])
	}
	if claims["client_id"] != "client" {
		t.Errorf("unexpected client_id: %v", claims["client_id"])
	}
	if claims["exp"] == nil {
		t.Error("expected exp claim")
	}
	if claims["iat"] == nil {
		t.Error("expected iat claim")
	}
	if claims["jti"] == nil {
		t.Error("expected jti claim")
	}
}
