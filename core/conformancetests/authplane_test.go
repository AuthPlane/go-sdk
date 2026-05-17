package conformancetests

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

func TestAuthplaneAgentIDMustBeExposedAsFirstClassField(t *testing.T) {
	Case(t, "authplane-agent-id-must-be-exposed-as-first-class-field")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://oauth.example.com", "https://api.example.com")

	// Token with agent_id claim.
	claims := testutil.StandardClaims("https://oauth.example.com", "https://api.example.com", "user123", "client456")
	claims["agent_id"] = "research-agent"
	token, err := testutil.SignToken(claims, key, jose.ES256, "key-0")
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	result, err := tv.VerifyToken(ctx, token, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if result.AgentID() != "research-agent" {
		t.Errorf("AgentID() = %q, want %q", result.AgentID(), "research-agent")
	}

	// When agent_id is absent, default must be empty string.
	claimsNoAgent := testutil.StandardClaims("https://oauth.example.com", "https://api.example.com", "user123", "client456")
	tokenNoAgent, err := testutil.SignToken(claimsNoAgent, key, jose.ES256, "key-0")
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	resultNoAgent, err := tv.VerifyToken(ctx, tokenNoAgent, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if resultNoAgent.AgentID() != "" {
		t.Errorf("AgentID() = %q, want empty string when absent", resultNoAgent.AgentID())
	}
}

func TestAuthplaneAgentChainMustBeExposedAsFirstClassField(t *testing.T) {
	Case(t, "authplane-agent-chain-must-be-exposed-as-first-class-field")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://oauth.example.com", "https://api.example.com")

	// Token with agent_chain claim.
	claims := testutil.StandardClaims("https://oauth.example.com", "https://api.example.com", "user123", "client456")
	claims["agent_chain"] = []string{"orchestrator", "research-agent", "summarizer"}
	token, err := testutil.SignToken(claims, key, jose.ES256, "key-0")
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	result, err := tv.VerifyToken(ctx, token, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	chain := result.AgentChain()
	expected := []string{"orchestrator", "research-agent", "summarizer"}
	if len(chain) != len(expected) {
		t.Fatalf("AgentChain() length = %d, want %d", len(chain), len(expected))
	}
	for i, v := range expected {
		if chain[i] != v {
			t.Errorf("AgentChain()[%d] = %q, want %q", i, chain[i], v)
		}
	}

	// When agent_chain is absent, default must be empty/nil slice.
	claimsNoChain := testutil.StandardClaims("https://oauth.example.com", "https://api.example.com", "user123", "client456")
	tokenNoChain, err := testutil.SignToken(claimsNoChain, key, jose.ES256, "key-0")
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	resultNoChain, err := tv.VerifyToken(ctx, tokenNoChain, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(resultNoChain.AgentChain()) != 0 {
		t.Errorf("AgentChain() = %v, want empty when absent", resultNoChain.AgentChain())
	}
}

func TestAuthplaneNBFMustBeExposedAsTypedFieldOnVerifiedClaims(t *testing.T) {
	Case(t, "authplane-nbf-must-be-exposed-as-typed-field-on-verified-claims")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://oauth.example.com", "https://api.example.com")

	// Token with nbf in the past (so it's valid now).
	nbfValue := time.Now().Add(-10 * time.Minute).Unix()
	claims := testutil.StandardClaims("https://oauth.example.com", "https://api.example.com", "user123", "client456")
	claims["nbf"] = nbfValue
	token, err := testutil.SignToken(claims, key, jose.ES256, "key-0")
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	result, err := tv.VerifyToken(ctx, token, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if result.NotBefore() != nbfValue {
		t.Errorf("NotBefore() = %d, want %d", result.NotBefore(), nbfValue)
	}

	// When nbf is absent, default must be 0.
	claimsNoNBF := testutil.StandardClaims("https://oauth.example.com", "https://api.example.com", "user123", "client456")
	tokenNoNBF, err := testutil.SignToken(claimsNoNBF, key, jose.ES256, "key-0")
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	resultNoNBF, err := tv.VerifyToken(ctx, tokenNoNBF, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if resultNoNBF.NotBefore() != 0 {
		t.Errorf("NotBefore() = %d, want 0 when absent", resultNoNBF.NotBefore())
	}
}
