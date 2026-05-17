package authplanehttp_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/http/pkg/authplanehttp"
	"github.com/go-jose/go-jose/v4"
)

const testResource = "http://localhost:8080/mcp"

type testEnv struct {
	adapter *authplanehttp.Adapter
	key     *rsa.PrivateKey
	issuer  string
	kid     string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	const kid = "test-key"
	jwksBody := mustMarshal(t, map[string]any{
		"keys": []any{rsaJWK(&key.PublicKey, kid)},
	})
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBody)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(mustMarshal(t, map[string]any{
			"issuer":         srv.URL,
			"jwks_uri":       srv.URL + "/.well-known/jwks.json",
			"token_endpoint": srv.URL + "/oauth/token",
		}))
	})
	client, err := authplane.NewClient(context.Background(), srv.URL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	res, err := client.Resource(testResource,
		resource.WithScopes("tools/add", "tools/multiply"),
		resource.WithVerifierOptions(verifier.WithInboundDPoP(verifier.InboundDPoPOptions{
			ReplayStore: verifier.NewInMemoryDPoPReplayStore(),
		})),
	)
	if err != nil {
		t.Fatalf("client.Resource: %v", err)
	}
	adapter := authplanehttp.New(res)
	return &testEnv{adapter: adapter, key: key, issuer: srv.URL, kid: kid}
}

func (e *testEnv) makeToken(t *testing.T, scopes []string, exp time.Time) string {
	t.Helper()
	headerJSON := mustMarshal(t, map[string]string{"alg": "RS256", "typ": "at+jwt", "kid": e.kid})
	claimsJSON := mustMarshal(t, map[string]any{
		"iss": e.issuer, "aud": testResource, "sub": "user-test",
		"jti": "jti-" + time.Now().Format(time.RFC3339Nano), "client_id": testResource,
		"iat": time.Now().Unix(), "exp": exp.Unix(), "scope": strings.Join(scopes, " "),
	})
	sigInput := b64url(headerJSON) + "." + b64url(claimsJSON)
	h := sha256.New()
	h.Write([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, e.key, crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return sigInput + "." + b64url(sig)
}

func (e *testEnv) makeTokenWithCnf(t *testing.T, scopes []string, exp time.Time, cnf map[string]any) string {
	t.Helper()
	headerJSON := mustMarshal(t, map[string]string{"alg": "RS256", "typ": "at+jwt", "kid": e.kid})
	claims := map[string]any{
		"iss": e.issuer, "aud": testResource, "sub": "user-test",
		"jti": "jti-" + time.Now().Format(time.RFC3339Nano), "client_id": testResource,
		"iat": time.Now().Unix(), "exp": exp.Unix(), "scope": strings.Join(scopes, " "),
	}
	if cnf != nil {
		claims["cnf"] = cnf
	}
	claimsJSON := mustMarshal(t, claims)
	sigInput := b64url(headerJSON) + "." + b64url(claimsJSON)
	h := sha256.New()
	h.Write([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, e.key, crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return sigInput + "." + b64url(sig)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

func rsaJWK(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": b64url(pub.N.Bytes()), "e": b64url(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// ecTestEnv is a test environment that uses an ES256 (P-256 ECDSA) signing key.
type ecTestEnv struct {
	adapter *authplanehttp.Adapter
	key     *ecdsa.PrivateKey
	issuer  string
	kid     string
}

func newECTestEnv(t *testing.T) *ecTestEnv {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	const kid = "test-ec-key"
	jwksBody := mustMarshal(t, map[string]any{
		"keys": []any{ecJWK(&key.PublicKey, kid)},
	})
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBody)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(mustMarshal(t, map[string]any{
			"issuer":         srv.URL,
			"jwks_uri":       srv.URL + "/.well-known/jwks.json",
			"token_endpoint": srv.URL + "/oauth/token",
		}))
	})
	client, err := authplane.NewClient(context.Background(), srv.URL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	res, err := client.Resource(testResource,
		resource.WithScopes("tools/add", "tools/multiply"),
		resource.WithVerifierOptions(verifier.WithInboundDPoP(verifier.InboundDPoPOptions{
			ReplayStore: verifier.NewInMemoryDPoPReplayStore(),
		})),
	)
	if err != nil {
		t.Fatalf("client.Resource: %v", err)
	}
	adapter := authplanehttp.New(res)
	return &ecTestEnv{adapter: adapter, key: key, issuer: srv.URL, kid: kid}
}

func (e *ecTestEnv) makeToken(t *testing.T, scopes []string, exp time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: e.key},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", e.kid),
	)
	if err != nil {
		t.Fatalf("create ES256 signer: %v", err)
	}
	payload := mustMarshal(t, map[string]any{
		"iss": e.issuer, "aud": testResource, "sub": "user-test",
		"jti": "jti-" + time.Now().Format(time.RFC3339Nano), "client_id": testResource,
		"iat": time.Now().Unix(), "exp": exp.Unix(), "scope": strings.Join(scopes, " "),
	})
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign ES256 JWT: %v", err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize ES256 JWT: %v", err)
	}
	return token
}

// ecJWK builds a JWK map for an EC P-256 public key using go-jose marshaling
// to avoid deprecated direct field access on ecdsa.PublicKey.
func ecJWK(pub *ecdsa.PublicKey, kid string) map[string]any {
	jwk := jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: "ES256", Use: "sig"}
	b, _ := jwk.MarshalJSON()
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
