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
func (c *VerifiedClaims) RequireScope(scope string) error {
	if !c.HasScope(scope) {
		return fmt.Errorf("%w: required %q", ErrInsufficientScope, scope)
	}
	return nil
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
