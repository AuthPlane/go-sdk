package verifier

import (
	"errors"
	"testing"
)

func testClaims() map[string]any {
	return map[string]any{
		"sub":         "user-123",
		"client_id":   "client-abc",
		"iss":         "https://auth.example.com",
		"aud":         "https://api.example.com",
		"exp":         float64(1700000000),
		"iat":         float64(1699990000),
		"jti":         "token-jti-1",
		"scope":       "read write admin",
		"agent_id":    "agent-1",
		"agent_chain": []any{"agent-1", "agent-2"},
		"cnf":         map[string]any{"jkt": "thumb-abc"},
		"act":         map[string]any{"sub": "delegator"},
		"may_act":     map[string]any{"sub": "potential-actor"},
		"custom":      "value",
	}
}

func TestVerifiedClaims_BasicAccessors(t *testing.T) {
	c := ParseClaims(testClaims(), "kid-1")

	if c.Sub() != "user-123" {
		t.Errorf("Sub: expected 'user-123', got %q", c.Sub())
	}
	if c.ClientID() != "client-abc" {
		t.Errorf("ClientID: expected 'client-abc', got %q", c.ClientID())
	}
	if c.Issuer() != "https://auth.example.com" {
		t.Errorf("Issuer: expected 'https://auth.example.com', got %q", c.Issuer())
	}
	if c.JTI() != "token-jti-1" {
		t.Errorf("JTI: expected 'token-jti-1', got %q", c.JTI())
	}
	if c.KID() != "kid-1" {
		t.Errorf("KID: expected 'kid-1', got %q", c.KID())
	}
	if c.ExpiresAt() != 1700000000 {
		t.Errorf("ExpiresAt: expected 1700000000, got %d", c.ExpiresAt())
	}
	if c.IssuedAt() != 1699990000 {
		t.Errorf("IssuedAt: expected 1699990000, got %d", c.IssuedAt())
	}
	if c.AgentID() != "agent-1" {
		t.Errorf("AgentID: expected 'agent-1', got %q", c.AgentID())
	}
}

func TestVerifiedClaims_Scopes(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	scopes := c.Scopes()
	if len(scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %d", len(scopes))
	}
	if scopes[0] != "read" || scopes[1] != "write" || scopes[2] != "admin" {
		t.Errorf("unexpected scopes: %v", scopes)
	}
}

func TestVerifiedClaims_Scopes_ReturnsCopy(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	scopes := c.Scopes()
	scopes[0] = "MUTATED"
	if c.Scopes()[0] == "MUTATED" {
		t.Error("Scopes() should return a copy")
	}
}

func TestVerifiedClaims_Audience(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	aud := c.Audience()
	if len(aud) != 1 || aud[0] != "https://api.example.com" {
		t.Errorf("unexpected audience: %v", aud)
	}
}

func TestVerifiedClaims_Audience_Array(t *testing.T) {
	raw := testClaims()
	raw["aud"] = []any{"aud1", "aud2"}
	c := ParseClaims(raw, "kid")
	aud := c.Audience()
	if len(aud) != 2 || aud[0] != "aud1" || aud[1] != "aud2" {
		t.Errorf("unexpected audience: %v", aud)
	}
}

func TestVerifiedClaims_Audience_ReturnsCopy(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	aud := c.Audience()
	aud[0] = "MUTATED"
	if c.Audience()[0] == "MUTATED" {
		t.Error("Audience() should return a copy")
	}
}

func TestVerifiedClaims_AgentChain(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	chain := c.AgentChain()
	if len(chain) != 2 || chain[0] != "agent-1" || chain[1] != "agent-2" {
		t.Errorf("unexpected agent chain: %v", chain)
	}
}

func TestVerifiedClaims_HasScope(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	if !c.HasScope("read") {
		t.Error("expected HasScope('read') = true")
	}
	if c.HasScope("delete") {
		t.Error("expected HasScope('delete') = false")
	}
}

func TestVerifiedClaims_RequireScope(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	if err := c.RequireScope("read"); err != nil {
		t.Errorf("RequireScope('read') should succeed: %v", err)
	}
	err := c.RequireScope("delete")
	if err == nil {
		t.Error("RequireScope('delete') should fail")
	}
	if !errors.Is(err, ErrInsufficientScope) {
		t.Errorf("expected ErrInsufficientScope, got %v", err)
	}
}

func TestVerifiedClaims_HasClaim(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	if !c.HasClaim("custom") {
		t.Error("expected HasClaim('custom') = true")
	}
	if c.HasClaim("nonexistent") {
		t.Error("expected HasClaim('nonexistent') = false")
	}
}

func TestVerifiedClaims_HasClaimValue(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	if !c.HasClaimValue("custom", "value") {
		t.Error("expected HasClaimValue('custom', 'value') = true")
	}
	if c.HasClaimValue("custom", "other") {
		t.Error("expected HasClaimValue('custom', 'other') = false")
	}
}

func TestVerifiedClaims_Claim(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	if c.Claim("custom") != "value" {
		t.Errorf("expected 'value', got %v", c.Claim("custom"))
	}
	if c.Claim("nonexistent") != nil {
		t.Error("expected nil for missing claim")
	}
}

func TestVerifiedClaims_DPoP(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	if !c.IsDPoPBound() {
		t.Error("expected IsDPoPBound() = true")
	}
	if c.DPoPThumbprint() != "thumb-abc" {
		t.Errorf("expected thumbprint 'thumb-abc', got %q", c.DPoPThumbprint())
	}
}

func TestVerifiedClaims_DPoP_NoCnf(t *testing.T) {
	raw := map[string]any{"sub": "user"}
	c := ParseClaims(raw, "kid")
	if c.IsDPoPBound() {
		t.Error("expected IsDPoPBound() = false without cnf")
	}
	if c.DPoPThumbprint() != "" {
		t.Error("expected empty thumbprint without cnf")
	}
}

func TestVerifiedClaims_Act(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	act := c.Act()
	if act["sub"] != "delegator" {
		t.Errorf("expected act.sub = 'delegator', got %v", act["sub"])
	}
}

func TestVerifiedClaims_MayAct(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	mayAct := c.MayAct()
	if mayAct["sub"] != "potential-actor" {
		t.Errorf("expected may_act.sub = 'potential-actor', got %v", mayAct["sub"])
	}
}

func TestVerifiedClaims_Raw_ReturnsCopy(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	raw := c.Raw()
	raw["MUTATED"] = true
	if c.Raw()["MUTATED"] != nil {
		t.Error("Raw() should return a copy")
	}
}

func TestVerifiedClaims_Cnf_ReturnsCopy(t *testing.T) {
	c := ParseClaims(testClaims(), "kid")
	cnf := c.Cnf()
	cnf["MUTATED"] = true
	if c.Cnf()["MUTATED"] != nil {
		t.Error("Cnf() should return a copy")
	}
}

func TestParseClaims_MissingFields(t *testing.T) {
	raw := map[string]any{}
	c := ParseClaims(raw, "")
	if c.Sub() != "" {
		t.Error("expected empty Sub for missing claim")
	}
	if c.ExpiresAt() != 0 {
		t.Error("expected 0 ExpiresAt for missing claim")
	}
	if c.Scopes() != nil {
		t.Error("expected nil Scopes for missing scope claim")
	}
	if c.Cnf() != nil {
		t.Error("expected nil Cnf for missing cnf claim")
	}
}
