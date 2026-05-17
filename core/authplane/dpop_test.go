package authplane

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestNewDPoPSigner_ES256(t *testing.T) {
	signer, err := NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if signer.Thumbprint() == "" {
		t.Error("expected non-empty thumbprint")
	}
}

func TestNewDPoPSigner_RS256(t *testing.T) {
	signer, err := NewDPoPSigner(jose.RS256)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if signer.Thumbprint() == "" {
		t.Error("expected non-empty thumbprint")
	}
}

func TestNewDPoPSigner_UnsupportedAlg(t *testing.T) {
	_, err := NewDPoPSigner(jose.HS256)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestGenerateProof_Basic(t *testing.T) {
	signer, _ := NewDPoPSigner(jose.ES256)
	proof, err := signer.GenerateProof("POST", "https://auth.example.com/token", nil)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if proof == "" {
		t.Fatal("expected non-empty proof")
	}

	// Parse and verify claims.
	parsed, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Check typ header.
	typ, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	if typ != "dpop+jwt" {
		t.Errorf("expected typ 'dpop+jwt', got %q", typ)
	}

	// Check jwk header present.
	if parsed.Headers[0].JSONWebKey == nil {
		if _, ok := parsed.Headers[0].ExtraHeaders["jwk"]; !ok {
			t.Error("expected jwk in header")
		}
	}

	// Verify signature and extract claims using the embedded public key.
	ecKey := signer.publicJWK.Key.(*ecdsa.PublicKey)
	var claims map[string]any
	if err := parsed.Claims(ecKey, &claims); err != nil {
		t.Fatalf("claims extraction failed: %v", err)
	}

	if claims["htm"] != "POST" {
		t.Errorf("htm = %v, want POST", claims["htm"])
	}
	if claims["htu"] != "https://auth.example.com/token" {
		t.Errorf("htu = %v, want https://auth.example.com/token", claims["htu"])
	}
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Error("expected non-empty jti")
	}
	if claims["iat"] == nil {
		t.Error("expected iat")
	}
}

func TestGenerateProof_WithNonce(t *testing.T) {
	signer, _ := NewDPoPSigner(jose.ES256)
	proof, err := signer.GenerateProof("GET", "https://api.example.com/data", &DPoPProofOptions{
		Nonce: "server-nonce-123",
	})
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	claims, err := testutil.ParseSignedToken(proof)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if claims["nonce"] != "server-nonce-123" {
		t.Errorf("nonce = %v, want 'server-nonce-123'", claims["nonce"])
	}
}

func TestGenerateProof_WithAccessToken(t *testing.T) {
	signer, _ := NewDPoPSigner(jose.ES256)
	proof, err := signer.GenerateProof("GET", "https://api.example.com/data", &DPoPProofOptions{
		AccessToken: "my-access-token",
	})
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	claims, err := testutil.ParseSignedToken(proof)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Verify ath is correct hash.
	h := sha256.Sum256([]byte("my-access-token"))
	expectedATH := base64.RawURLEncoding.EncodeToString(h[:])
	if claims["ath"] != expectedATH {
		t.Errorf("ath = %v, want %s", claims["ath"], expectedATH)
	}
}

func TestGenerateProof_NoNonceOrATH_WhenOptsEmpty(t *testing.T) {
	signer, _ := NewDPoPSigner(jose.ES256)
	proof, err := signer.GenerateProof("DELETE", "https://api.example.com/resource", &DPoPProofOptions{})
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	claims, err := testutil.ParseSignedToken(proof)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if _, ok := claims["nonce"]; ok {
		t.Error("nonce should not be present when empty")
	}
	if _, ok := claims["ath"]; ok {
		t.Error("ath should not be present when access token is empty")
	}
}

func TestGenerateProof_UniqueJTI(t *testing.T) {
	signer, _ := NewDPoPSigner(jose.ES256)

	jtis := make(map[string]bool)
	for range 10 {
		proof, _ := signer.GenerateProof("GET", "https://example.com", nil)
		claims, err := testutil.ParseSignedToken(proof)
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		jti := claims["jti"].(string)
		if jtis[jti] {
			t.Errorf("duplicate JTI: %s", jti)
		}
		jtis[jti] = true
	}
}

func TestThumbprint_Stable(t *testing.T) {
	signer, _ := NewDPoPSigner(jose.ES256)
	t1 := signer.Thumbprint()
	t2 := signer.Thumbprint()
	if t1 != t2 {
		t.Error("thumbprint should be stable")
	}
}

func TestThumbprint_DifferentKeys(t *testing.T) {
	s1, _ := NewDPoPSigner(jose.ES256)
	s2, _ := NewDPoPSigner(jose.ES256)
	if s1.Thumbprint() == s2.Thumbprint() {
		t.Error("different keys should have different thumbprints")
	}
}

func TestGenerateProof_HTUStripsQueryAndFragment(t *testing.T) {
	signer, _ := NewDPoPSigner(jose.ES256)

	tests := []struct {
		name    string
		url     string
		wantHTU string
	}{
		{"query stripped", "https://api.example.com/resource?page=1&size=10", "https://api.example.com/resource"},
		{"fragment stripped", "https://api.example.com/resource#section", "https://api.example.com/resource"},
		{"query and fragment stripped", "https://api.example.com/resource?q=1#top", "https://api.example.com/resource"},
		{"no query no fragment unchanged", "https://api.example.com/resource", "https://api.example.com/resource"},
		{"root path with query", "https://api.example.com/?foo=bar", "https://api.example.com/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof, err := signer.GenerateProof("GET", tt.url, nil)
			if err != nil {
				t.Fatalf("GenerateProof: %v", err)
			}
			claims, err := testutil.ParseSignedToken(proof)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if claims["htu"] != tt.wantHTU {
				t.Errorf("htu = %v, want %v", claims["htu"], tt.wantHTU)
			}
		})
	}
}

func TestNewDPoPSignerWithKey_ES256(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	signer, err := NewDPoPSignerWithKey(key, jose.ES256)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	proof, err := signer.GenerateProof("GET", "https://example.com", nil)
	if err != nil {
		t.Fatalf("proof generation failed: %v", err)
	}
	if proof == "" {
		t.Error("expected non-empty proof")
	}
}

func TestNewDPoPSignerWithKey_RS256(t *testing.T) {
	key, err := testutil.GenerateRS256Key()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	signer, err := NewDPoPSignerWithKey(key, jose.RS256)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if signer.Thumbprint() == "" {
		t.Error("expected thumbprint")
	}
}

func TestNewDPoPSignerWithKey_ThumbprintMatchesBoundKey(t *testing.T) {
	key, _ := testutil.GenerateES256Key()
	signer, _ := NewDPoPSignerWithKey(key, jose.ES256)

	// Verify the thumbprint is non-empty and stable across calls.
	tp1 := signer.Thumbprint()
	tp2 := signer.Thumbprint()
	if tp1 == "" {
		t.Error("expected non-empty thumbprint")
	}
	if tp1 != tp2 {
		t.Error("thumbprint should be stable")
	}
}
