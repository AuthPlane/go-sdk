package authplane

import "github.com/authplane/go-sdk/core/resource/verifier"

// ErrInvalidIssuer is returned when the issuer identifier is not the shape RFC
// 8414 requires: §2 forbids a query and a fragment component, and the
// identifier must be an absolute URL with a scheme and host.
//
// It is the same sentinel value verifier.ErrInvalidIssuer names, so errors.Is
// matches whether the rejection came from NewClient or from the authoritative
// gate in verifier.NewTokenVerifier.
var ErrInvalidIssuer = verifier.ErrInvalidIssuer
