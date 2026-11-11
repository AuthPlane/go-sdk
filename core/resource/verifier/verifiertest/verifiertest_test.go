package verifiertest_test

import (
	"testing"

	"github.com/authplane/go-sdk/core/resource/verifier/verifiertest"
)

func TestNewClaims_A91(t *testing.T) {
	claims, err := verifiertest.NewClaims(map[string]any{"sub": "admin", "scope": "read write", "custom": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub() != "admin" || !claims.HasScope("write") || claims.Claim("custom") != "x" {
		t.Errorf("claims = %+v", claims.Raw())
	}
	if _, err := verifiertest.NewClaims(map[string]any{"exp": 1}); err == nil {
		t.Error("an expired token must still be refused: this is real verification")
	}
	if _, err := verifiertest.NewClaims(map[string]any{"aud": []string{"a"}}); err == nil {
		t.Error("want an error for a non-string aud")
	}
}
