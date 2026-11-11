package verifier_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/authplane/go-sdk/core/resource/verifier"
)

func TestWithLogger_ReceivesFailOpenWarning_A102(t *testing.T) {
	var logs bytes.Buffer
	v, key := setupES256Verifier(t,
		verifier.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))),
		verifier.WithRevocationChecker(func(context.Context, *verifier.VerifiedClaims, string) (bool, error) {
			return false, errors.New("down")
		}))
	if _, err := v.VerifyToken(context.Background(), signStandardToken(t, key), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "fail-open") {
		t.Errorf("logs = %q", logs.String())
	}
}

func TestVerifyToken_DPoPSchemeOnBearerOnlyResource_A95(t *testing.T) {
	v, key := setupES256Verifier(t)
	dpop, err := verifier.NewDPoPContext("GET", "https://api.example.com/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	dpop.SchemeDPoP = true
	if _, err := v.VerifyToken(context.Background(), signStandardToken(t, key), dpop); !errors.Is(err, verifier.ErrDPoPNotSupported) {
		t.Errorf("err = %v", err)
	}
}

func TestClaim_ReturnsACopy_A106(t *testing.T) {
	claims := verifier.ParseClaimsForTest(map[string]any{"org": map[string]any{"role": "reader"}, "big": float64(1 << 53)}, "k")
	claims.Claim("org").(map[string]any)["role"] = "admin"
	if got := claims.Claim("org").(map[string]any)["role"]; got != "reader" {
		t.Errorf("a caller's write reached the claims: %v", got)
	}
	if got := claims.Raw()["big"]; got != float64(1<<53) {
		t.Errorf("big = %v", got)
	}
}
