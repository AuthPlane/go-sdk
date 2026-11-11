package verifier

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

const explicitAccessTokenType = "at+jwt"

// defaultRequiredClaims beyond the claims that are always required (RFC 9068 section 2.2).
var defaultRequiredClaims = []string{"iat", "jti", "client_id"}

func normalizeTokenType(t string) string {
	return strings.TrimPrefix(strings.ToLower(t), "application/")
}

// checkTokenType enforces the accepted typ values and reports whether the token is
// explicitly typed as an access token.
func (v *TokenVerifier) checkTokenType(header jose.Header) (bool, error) {
	raw, present := header.ExtraHeaders[jose.HeaderType]
	if !present {
		if v.acceptNoType {
			return false, nil
		}
		return false, fmt.Errorf("%w: missing typ, expected %q", ErrInvalidClaims, explicitAccessTokenType)
	}
	typ, isString := raw.(string)
	if !isString {
		return false, fmt.Errorf("%w: typ is not a string", ErrInvalidClaims)
	}
	normalized := normalizeTokenType(typ)
	if normalized == "" {
		return false, fmt.Errorf("%w: empty typ", ErrInvalidClaims)
	}
	accepted := v.tokenTypes
	if accepted == nil && !v.acceptNoType {
		accepted = []string{explicitAccessTokenType}
	}
	if !slices.Contains(accepted, normalized) {
		return false, fmt.Errorf("%w: invalid typ %q", ErrInvalidClaims, typ)
	}
	return normalized == explicitAccessTokenType, nil
}

// applyClaimPolicy maps configured scope and client claims onto the parsed claims.
// With the defaults it changes nothing.
func (v *TokenVerifier) applyClaimPolicy(claims *VerifiedClaims) error {
	if v.scopeClaims != nil {
		scopes, err := scopesFromClaims(claims.raw, v.scopeClaims)
		if err != nil {
			return err
		}
		claims.scopes = scopes
	}
	if v.clientClaims != nil {
		claims.clientID = ""
		for _, name := range v.clientClaims {
			if id, _ := claims.raw[name].(string); id != "" {
				claims.clientID = id
				break
			}
		}
	}
	return nil
}

func scopesFromClaims(raw map[string]any, names []string) ([]string, error) {
	var scopes []string
	add := func(scope string) {
		if !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	for _, name := range names {
		value, present := raw[name]
		if !present {
			continue
		}
		switch shaped := value.(type) {
		case string:
			for _, scope := range strings.Fields(shaped) {
				add(scope)
			}
		case []any:
			for _, item := range shaped {
				scope, isString := item.(string)
				if !isString {
					return nil, fmt.Errorf("%w: claim %q holds a non-string scope", ErrInvalidClaims, name)
				}
				add(scope)
			}
		default:
			return nil, fmt.Errorf("%w: claim %q is neither a string nor an array of strings", ErrInvalidClaims, name)
		}
	}
	return scopes, nil
}

// checkNotIDToken refuses a token without explicit typing that looks like an ID token
// or carries nothing that marks it as an access token. See WithAcceptedTokenTypes.
func (v *TokenVerifier) checkNotIDToken(claims *VerifiedClaims) error {
	for _, name := range []string{"nonce", "at_hash", "c_hash"} {
		if _, present := claims.raw[name]; present {
			return fmt.Errorf("%w: claim %q marks an ID token", ErrInvalidClaims, name)
		}
	}
	if value, present := claims.raw["typ"]; present {
		if typ, isString := value.(string); !isString || !strings.EqualFold(typ, "Bearer") {
			return fmt.Errorf("%w: payload typ is not Bearer", ErrInvalidClaims)
		}
	}
	for _, name := range v.accessTokenMarkers() {
		if value, present := claims.raw[name]; present && value != nil {
			return nil
		}
	}
	return fmt.Errorf("%w: no claim marks this as an access token", ErrInvalidClaims)
}

func (v *TokenVerifier) accessTokenMarkers() []string {
	if v.markerClaims != nil {
		return v.markerClaims
	}
	scopes, clients := v.scopeClaims, v.clientClaims
	if scopes == nil {
		scopes = []string{"scope"}
	}
	if clients == nil {
		clients = []string{"client_id"}
	}
	markers := slices.Clone(scopes)
	for _, name := range clients {
		if name != "azp" {
			markers = append(markers, name)
		}
	}
	return markers
}

func (v *TokenVerifier) checkRequiredClaims(claims *VerifiedClaims) error {
	missing := func(name string) error {
		return fmt.Errorf("%w: missing required claim %q", ErrInvalidClaims, name)
	}
	switch {
	case claims.Issuer() == "":
		return missing("iss")
	case claims.Sub() == "":
		return missing("sub")
	case len(claims.Audience()) == 0:
		return missing("aud")
	case claims.ExpiresAt() == 0:
		return missing("exp")
	}
	required := v.requiredClaims
	if required == nil {
		required = defaultRequiredClaims
	}
	for _, name := range required {
		if !claimPresent(claims, name) {
			return missing(name)
		}
	}
	return nil
}

func claimPresent(claims *VerifiedClaims, name string) bool {
	switch name {
	case "iat":
		return claims.IssuedAt() != 0
	case "nbf":
		return claims.NotBefore() != 0
	case "jti":
		return claims.JTI() != ""
	case "client_id":
		id, _ := claims.raw["client_id"].(string)
		return id != ""
	}
	value, present := claims.raw[name]
	if !present || value == nil {
		return false
	}
	if s, isString := value.(string); isString {
		return s != ""
	}
	return true
}
