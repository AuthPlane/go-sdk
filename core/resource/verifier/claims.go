// Package verifier provides JWT access token verification (RFC 9068).
package verifier

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// VerifiedClaims holds the validated claims from a JWT access token.
// All fields are unexported; use accessor methods to read values.
// Returned slices and maps are copies to prevent mutation.
type VerifiedClaims struct {
	sub        string
	clientID   string
	issuer     string
	jti        string
	kid        string
	agentID    string
	scopes     []string
	audience   []string
	agentChain []string
	expiresAt  int64
	issuedAt   int64
	notBefore  int64
	cnf        map[string]any
	act        map[string]any
	mayAct     map[string]any
	raw        map[string]any
	dpopProof  *VerifiedDPoPProof
}

// Sub returns the subject (sub) claim.
func (c *VerifiedClaims) Sub() string { return c.sub }

// ClientID returns the client_id claim.
func (c *VerifiedClaims) ClientID() string { return c.clientID }

// Issuer returns the issuer (iss) claim.
func (c *VerifiedClaims) Issuer() string { return c.issuer }

// JTI returns the JWT ID (jti) claim.
func (c *VerifiedClaims) JTI() string { return c.jti }

// KID returns the key ID from the JWT header.
func (c *VerifiedClaims) KID() string { return c.kid }

// AgentID returns the agent_id claim.
func (c *VerifiedClaims) AgentID() string { return c.agentID }

// ExpiresAt returns the expiration time (exp) claim as Unix seconds.
func (c *VerifiedClaims) ExpiresAt() int64 { return c.expiresAt }

// IssuedAt returns the issued-at (iat) claim as Unix seconds.
func (c *VerifiedClaims) IssuedAt() int64 { return c.issuedAt }

// NotBefore returns the not-before (nbf) claim as Unix seconds.
func (c *VerifiedClaims) NotBefore() int64 { return c.notBefore }

// Scopes returns a copy of the token's scopes.
func (c *VerifiedClaims) Scopes() []string {
	return slices.Clone(c.scopes)
}

// Audience returns a copy of the audience (aud) claim.
func (c *VerifiedClaims) Audience() []string {
	return slices.Clone(c.audience)
}

// AgentChain returns a copy of the agent_chain claim.
func (c *VerifiedClaims) AgentChain() []string {
	return slices.Clone(c.agentChain)
}

// Cnf returns a copy of the confirmation (cnf) claim.
func (c *VerifiedClaims) Cnf() map[string]any {
	return cloneMap(c.cnf)
}

// Act returns a copy of the actor (act) claim.
func (c *VerifiedClaims) Act() map[string]any {
	return cloneMap(c.act)
}

// MayAct returns a copy of the may_act claim.
func (c *VerifiedClaims) MayAct() map[string]any {
	return cloneMap(c.mayAct)
}

// Raw returns a copy of the raw claims map.
func (c *VerifiedClaims) Raw() map[string]any {
	return cloneMap(c.raw)
}

// HasScope returns true if the token has the given scope.
func (c *VerifiedClaims) HasScope(scope string) bool {
	return slices.Contains(c.scopes, scope)
}

// RequireScope returns ErrInsufficientScope if the token lacks the given scope.
//
// Thin wrapper over [RequireScopes] so the singular helper carries the
// same enriched `required scope "X"; token has scopes: …` shape the
// plural one does. The wire body produced from this path is byte-identical
// to a `claims.RequireScopes(scope)` call. Note that the adapter middleware
// at github.com/authplane/go-sdk/http/pkg/authplanehttp.Adapter.RequireScopes
// still loops over scopes and returns on the first miss, so a multi-scope
// adapter failure names only one scope; a direct
// `claims.RequireScopes("a", "b", ...)` call names every missing scope.
// The two paths converge only on the single-missing-scope case until the
// adapter is switched over to the plural helper.
func (c *VerifiedClaims) RequireScope(scope string) error {
	return c.RequireScopes(scope)
}

// RequireScopes returns ErrInsufficientScope unless the token carries every
// scope in scopes. Empty input is a no-op (no required scopes ⇒ always
// satisfied), matching the adapter-middleware
// github.com/authplane/go-sdk/http/pkg/authplanehttp.Adapter.RequireScopes
// semantic.
//
// On failure the returned error names every missing scope and the scopes
// the token does carry, so the adapter can surface it verbatim in the
// `error_description` of the `WWW-Authenticate` challenge without an
// out-of-band log lookup. The error wraps ErrInsufficientScope, so
// adapters that already branch on `errors.Is(err, ErrInsufficientScope)`
// (e.g. `resource.HTTPStatus`) keep producing a 403 with the right
// `scope="..."` parameter when the surrounding ScopeError carries the
// full required-scope list.
func (c *VerifiedClaims) RequireScopes(scopes ...string) error {
	if len(scopes) == 0 {
		return nil
	}
	var missing []string
	for _, scope := range scopes {
		if !c.HasScope(scope) {
			missing = append(missing, scope)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	plural := ""
	if len(missing) > 1 {
		plural = "s"
	}
	available := "(none)"
	if len(c.scopes) > 0 {
		available = strings.Join(c.scopes, " ")
	}
	return fmt.Errorf(
		"%w: required scope%s %s; token has scopes: %s",
		ErrInsufficientScope,
		plural,
		strings.Join(quoteAll(missing), ", "),
		available,
	)
}

// quoteAll wraps each entry in %q-style double-quotes so the rendered
// error_description visually delimits each scope and stays unambiguous
// even if a malformed token carries scope tokens containing control
// characters. RFC 6749 §3.3 (`scope-token = 1*( %x21 / %x23-5B /
// %x5D-7E )`) explicitly forbids whitespace inside a scope, so this is
// defense against non-conformant inputs rather than a spec-permitted
// case.
func quoteAll(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = fmt.Sprintf("%q", v)
	}
	return out
}

// HasClaim returns true if the raw claims contain the given key.
func (c *VerifiedClaims) HasClaim(key string) bool {
	_, ok := c.raw[key]
	return ok
}

// HasClaimValue returns true if the raw claims contain the given key with the given value.
func (c *VerifiedClaims) HasClaimValue(key string, value any) bool {
	v, ok := c.raw[key]
	if !ok {
		return false
	}
	return fmt.Sprintf("%v", v) == fmt.Sprintf("%v", value)
}

// Claim returns the raw claim value for the given key.
func (c *VerifiedClaims) Claim(key string) any {
	return c.raw[key]
}

// IsDPoPBound returns true if the token has a DPoP confirmation (cnf.jkt).
func (c *VerifiedClaims) IsDPoPBound() bool {
	if c.cnf == nil {
		return false
	}
	_, ok := c.cnf["jkt"]
	return ok
}

// DPoPThumbprint returns the DPoP JWK thumbprint from the cnf claim.
func (c *VerifiedClaims) DPoPThumbprint() string {
	if c.cnf == nil {
		return ""
	}
	jkt, _ := c.cnf["jkt"].(string)
	return jkt
}

// DPoPProof returns the validated DPoP proof attached to this token, or nil
// when the token is a bearer token or no DPoP context was supplied to
// VerifyToken. The returned pointer references an immutable snapshot — the
// verifier never mutates VerifiedDPoPProof after publication.
func (c *VerifiedClaims) DPoPProof() *VerifiedDPoPProof {
	return c.dpopProof
}

// ParseClaims parses a raw claims map (from JWT payload) into VerifiedClaims.
// kid is the key ID from the JWT header.
func ParseClaims(raw map[string]any, kid string) *VerifiedClaims {
	c := &VerifiedClaims{
		raw: cloneMap(raw),
		kid: kid,
	}

	c.sub, _ = raw["sub"].(string)
	c.clientID, _ = raw["client_id"].(string)
	c.issuer, _ = raw["iss"].(string)
	c.jti, _ = raw["jti"].(string)
	c.agentID, _ = raw["agent_id"].(string)

	// Parse exp and iat (JSON numbers are float64).
	if exp, ok := raw["exp"].(float64); ok {
		c.expiresAt = int64(exp)
	}
	if iat, ok := raw["iat"].(float64); ok {
		c.issuedAt = int64(iat)
	}
	if nbf, ok := raw["nbf"].(float64); ok {
		c.notBefore = int64(nbf)
	}

	// Parse audience (string or []string via JSON).
	switch aud := raw["aud"].(type) {
	case string:
		c.audience = []string{aud}
	case []any:
		for _, v := range aud {
			if s, ok := v.(string); ok {
				c.audience = append(c.audience, s)
			}
		}
	}

	// Parse scopes from space-delimited string.
	if scope, ok := raw["scope"].(string); ok {
		c.scopes = strings.Fields(scope)
	}

	// Parse agent_chain.
	if chain, ok := raw["agent_chain"].([]any); ok {
		for _, v := range chain {
			if s, ok := v.(string); ok {
				c.agentChain = append(c.agentChain, s)
			}
		}
	}

	// Parse structured claims.
	c.cnf = parseMapClaim(raw, "cnf")
	c.act = parseMapClaim(raw, "act")
	c.mayAct = parseMapClaim(raw, "may_act")

	return c
}

func parseMapClaim(raw map[string]any, key string) map[string]any {
	v, ok := raw[key]
	if !ok {
		return nil
	}
	// json.Unmarshal into map[string]any yields map[string]any for objects.
	if m, ok := v.(map[string]any); ok {
		return cloneMap(m)
	}
	return nil
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	data, _ := json.Marshal(m)
	var cp map[string]any
	_ = json.Unmarshal(data, &cp)
	return cp
}
