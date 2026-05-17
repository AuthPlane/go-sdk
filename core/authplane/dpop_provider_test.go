package authplane

import (
	"crypto/ecdsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// helper: create a signer and store for tests.
func newTestProvider(t *testing.T) (*dpopProvider, *DPoPSigner, DPoPNonceStore) {
	t.Helper()
	signer, err := NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	store := NewInMemoryDPoPNonceStore()
	provider := newDPoPProvider(signer, store)
	return provider, signer, store
}

// parseDPoPClaims parses a compact DPoP proof JWT and returns its claims using the
// embedded public key extracted from the JWK header.
func parseDPoPClaims(t *testing.T, proof string) map[string]any {
	t.Helper()
	parsed, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("jwt.ParseSigned: %v", err)
	}

	// Extract the public key from the embedded JWK header.
	jwkHeader := parsed.Headers[0].JSONWebKey
	if jwkHeader == nil {
		t.Fatal("expected jwk header in DPoP proof")
	}
	ecKey, ok := jwkHeader.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey in jwk header, got %T", jwkHeader.Key)
	}

	var claims map[string]any
	if err := parsed.Claims(ecKey, &claims); err != nil {
		t.Fatalf("Claims: %v", err)
	}
	return claims
}

// TestBuildHeaders_ReturnsDPoPHeader verifies BuildHeaders produces a "DPoP" key
// with a valid JWT that contains htm and htu claims.
func TestBuildHeaders_ReturnsDPoPHeader(t *testing.T) {
	provider, _, _ := newTestProvider(t)

	headers, err := provider.BuildHeaders("POST", "https://auth.example.com/token")
	if err != nil {
		t.Fatalf("BuildHeaders: %v", err)
	}

	proof, ok := headers["DPoP"]
	if !ok {
		t.Fatal("expected 'DPoP' key in returned headers")
	}
	if proof == "" {
		t.Fatal("DPoP header value must not be empty")
	}

	claims := parseDPoPClaims(t, proof)

	if claims["htm"] != "POST" {
		t.Errorf("htm = %v, want POST", claims["htm"])
	}
	if claims["htu"] != "https://auth.example.com/token" {
		t.Errorf("htu = %v, want https://auth.example.com/token", claims["htu"])
	}
}

// TestBuildHeaders_IncludesStoredNonce verifies that when the nonce store already
// has a nonce for the request's origin, BuildHeaders includes it in the proof.
func TestBuildHeaders_IncludesStoredNonce(t *testing.T) {
	provider, _, store := newTestProvider(t)

	rawURL := "https://auth.example.com/token"
	origin := originFromURL(rawURL)
	store.Put(origin, "server-issued-nonce-xyz")

	headers, err := provider.BuildHeaders("POST", rawURL)
	if err != nil {
		t.Fatalf("BuildHeaders: %v", err)
	}

	claims := parseDPoPClaims(t, headers["DPoP"])

	if claims["nonce"] != "server-issued-nonce-xyz" {
		t.Errorf("nonce = %v, want 'server-issued-nonce-xyz'", claims["nonce"])
	}
}

// TestBuildHeaders_OmitsNonceWhenStoreEmpty verifies that when the store has no
// nonce for the origin, the produced proof does not contain a "nonce" claim.
func TestBuildHeaders_OmitsNonceWhenStoreEmpty(t *testing.T) {
	provider, _, _ := newTestProvider(t)

	headers, err := provider.BuildHeaders("GET", "https://api.example.com/data")
	if err != nil {
		t.Fatalf("BuildHeaders: %v", err)
	}

	claims := parseDPoPClaims(t, headers["DPoP"])

	if _, ok := claims["nonce"]; ok {
		t.Error("nonce claim must not be present when the store is empty")
	}
}

// TestNoteNonce_StoresNonceRetrievableViaGet verifies that NoteNonce persists the
// nonce so that a subsequent store.Get for the same origin returns it.
func TestNoteNonce_StoresNonceRetrievableViaGet(t *testing.T) {
	provider, _, store := newTestProvider(t)

	rawURL := "https://auth.example.com/token"
	provider.NoteNonce(rawURL, "fresh-nonce-42")

	origin := originFromURL(rawURL)
	got := store.Get(origin)
	if got != "fresh-nonce-42" {
		t.Errorf("store.Get(%q) = %q, want 'fresh-nonce-42'", origin, got)
	}
}
