package verifier

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateIdentifier checks that value is an absolute http(s) URL identifier
// with a host and no fragment (RFC 8707 §2 forbids fragments in resource
// identifiers).
//
// It never rewrites the value: RFC 8414 §3.3 and RFC 9728 §3.3 require the
// advertised issuer/resource to be identical to the configured one — a simple
// string comparison — so trailing slashes, host case, and explicit ports are
// all legal variations that are preserved verbatim.
func ValidateIdentifier(value, label string) error {
	u, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %q: %w", label, value, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("%s must be an absolute http or https URL, got %q", label, value)
	}
	if u.Host == "" {
		return fmt.Errorf("%s must include a host, got %q", label, value)
	}
	if strings.Contains(value, "#") {
		return fmt.Errorf("%s must not contain a fragment, got %q", label, value)
	}
	return nil
}
