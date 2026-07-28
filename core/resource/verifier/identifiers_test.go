package verifier_test

import (
	"testing"

	"github.com/authplane/go-sdk/core/resource/verifier"
)

func TestValidateIdentifierAcceptsLegalVariations(t *testing.T) {
	// Trailing slashes, host case, and explicit ports are legal identifier
	// variations — preserved, never rejected or rewritten.
	for _, value := range []string{
		"https://auth.example.com",
		"https://auth.example.com/",
		"https://auth.example.com/tenant/",
		"https://Auth.Example.com:443/t1",
		"http://localhost:8080/issuer",
	} {
		if err := verifier.ValidateIdentifier(value, "issuer"); err != nil {
			t.Errorf("ValidateIdentifier(%q) = %v, want nil", value, err)
		}
	}
}

func TestValidateIdentifierRejectsStructurallyInvalid(t *testing.T) {
	for _, value := range []string{
		"auth.example.com",                 // no scheme
		"ftp://auth.example.com",           // non-http(s) scheme
		"https:example.com",                // no authority
		"https://api.example.com/mcp#frag", // fragment (RFC 8707 §2)
		"/mcp",                             // absolute path only
	} {
		if err := verifier.ValidateIdentifier(value, "issuer"); err == nil {
			t.Errorf("ValidateIdentifier(%q) = nil, want error", value)
		}
	}
}
