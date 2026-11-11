package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/internal/ssrf"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type assertionServer struct {
	*httptest.Server
	mu    sync.Mutex
	forms []url.Values
	reply func(n int, w http.ResponseWriter)
}

func newAssertionServer(t *testing.T, reply func(n int, w http.ResponseWriter)) *assertionServer {
	t.Helper()
	s := &assertionServer{reply: reply}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		s.mu.Lock()
		s.forms = append(s.forms, r.PostForm)
		n := len(s.forms)
		s.mu.Unlock()
		s.reply(n, w)
	}))
	t.Cleanup(s.Close)
	return s
}

func okToken(_ int, w http.ResponseWriter) {
	_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer"}`))
}

func jwtAuth(t *testing.T) (ClientAuthentication, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ClientAuthentication{
		Method:     ClientAuthPrivateKeyJWT,
		ClientID:   "client-1",
		SigningKey: key,
		SigningAlg: jose.ES256,
		KeyID:      "k1",
		issuer:     "https://as.example.com",
	}, key
}

// readAssertion verifies the assertion and returns its claims and typ.
func readAssertion(t *testing.T, form url.Values, key *ecdsa.PrivateKey) (map[string]any, string) {
	t.Helper()
	if form.Get("client_assertion_type") != clientAssertionType {
		t.Errorf("client_assertion_type = %q", form.Get("client_assertion_type"))
	}
	if form.Get("client_secret") != "" {
		t.Error("a secret was sent")
	}
	parsed, err := jwt.ParseSigned(form.Get("client_assertion"), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	var claims map[string]any
	if err := parsed.Claims(&key.PublicKey, &claims); err != nil {
		t.Fatalf("verify assertion: %v", err)
	}
	typ, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	return claims, typ
}

func TestPrivateKeyJWT_AssertionRules_A24(t *testing.T) {
	s := newAssertionServer(t, okToken)
	auth, key := jwtAuth(t)
	for range 2 {
		if _, err := ClientCredentials(context.Background(), s.URL, auth, ssrf.DevModeFetchSettings(), nil, nil, nil); err != nil {
			t.Fatalf("ClientCredentials: %v", err)
		}
	}
	first, typ := readAssertion(t, s.forms[0], key)
	second, _ := readAssertion(t, s.forms[1], key)

	if typ != "client-authentication+jwt" {
		t.Errorf("typ = %q", typ)
	}
	if first["iss"] != "client-1" || first["sub"] != "client-1" {
		t.Errorf("iss = %v, sub = %v", first["iss"], first["sub"])
	}
	if first["aud"] != "https://as.example.com" {
		t.Errorf("aud = %v, want the issuer as a string", first["aud"])
	}
	if exp := time.Unix(int64(first["exp"].(float64)), 0); time.Until(exp) > 61*time.Second {
		t.Errorf("exp is %v away", time.Until(exp))
	}
	if first["jti"] == second["jti"] {
		t.Error("two requests shared a jti")
	}
}

type stubDPoP struct{ notes *int }

func (stubDPoP) BuildHeaders(string, string) (map[string]string, error) {
	return map[string]string{"DPoP": "proof"}, nil
}

func (s stubDPoP) NoteNonce(string, string) { *s.notes++ }

func TestPrivateKeyJWT_NonceRetryHasNewJTI_A24(t *testing.T) {
	s := newAssertionServer(t, func(n int, w http.ResponseWriter) {
		if n == 1 {
			w.Header().Set("DPoP-Nonce", "nonce")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"a","token_type":"DPoP"}`))
	})
	auth, key := jwtAuth(t)
	if _, err := ClientCredentials(context.Background(), s.URL, auth, ssrf.DevModeFetchSettings(), nil, nil, stubDPoP{notes: new(int)}); err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if len(s.forms) != 2 {
		t.Fatalf("requests = %d, want 2", len(s.forms))
	}
	first, _ := readAssertion(t, s.forms[0], key)
	second, _ := readAssertion(t, s.forms[1], key)
	if first["jti"] == second["jti"] {
		t.Error("the retry replayed the jti")
	}
}

func TestPrivateKeyJWT_TokenEndpointAudienceOptIn_A76(t *testing.T) {
	s := newAssertionServer(t, func(_ int, w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"active":true,"access_token":"a","token_type":"Bearer"}`))
	})
	auth, key := jwtAuth(t)
	auth.AssertionAudienceTokenEndpoint = true
	ctx := context.Background()

	if _, err := ClientCredentials(ctx, s.URL, auth, ssrf.DevModeFetchSettings(), nil, nil, nil); err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	claims, _ := readAssertion(t, s.forms[0], key)
	if claims["aud"] != s.URL {
		t.Errorf("token request aud = %v, want the token endpoint", claims["aud"])
	}

	if _, err := Introspect(ctx, s.URL, auth, ssrf.DevModeFetchSettings(), "tok", nil); err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	claims, _ = readAssertion(t, s.forms[1], key)
	if claims["aud"] != "https://as.example.com" {
		t.Errorf("introspection aud = %v, want the issuer: an assertion for the token endpoint must not go elsewhere", claims["aud"])
	}
}

func TestValidateClientAuthentication_PrivateKeyJWT_A25(t *testing.T) {
	good, _ := jwtAuth(t)
	if err := ValidateClientAuthentication(good); err != nil {
		t.Errorf("valid: %v", err)
	}
	noKey := good
	noKey.SigningKey = nil
	if err := ValidateClientAuthentication(noKey); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("no key: err = %v", err)
	}
	for _, alg := range []jose.SignatureAlgorithm{"", "none", jose.HS256} {
		bad := good
		bad.SigningAlg = alg
		if err := ValidateClientAuthentication(bad); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("alg %q: err = %v", alg, err)
		}
	}
}

func TestTokenType_NotApplicableOnlyOnExchange_A22_A23(t *testing.T) {
	s := newAssertionServer(t, func(_ int, w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"access_token":"jag","token_type":"N_A","issued_token_type":"urn:ietf:params:oauth:token-type:id-jag"}`))
	})
	auth := ClientAuthentication{Method: ClientAuthClientSecretBasic, ClientID: "c", ClientSecret: "s"}
	ctx := context.Background()

	resp, err := TokenExchange(ctx, s.URL, auth, ssrf.DevModeFetchSettings(), TokenExchangeInput{SubjectToken: "t"}, nil)
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if resp.TokenType != "N_A" {
		t.Errorf("token_type = %q", resp.TokenType)
	}
	if _, err := ClientCredentials(ctx, s.URL, auth, ssrf.DevModeFetchSettings(), nil, nil, nil); !errors.Is(err, ErrProtocolError) {
		t.Errorf("client credentials: err = %v, want ErrProtocolError", err)
	}
}

func TestAuthorizationDetails_A26(t *testing.T) {
	s := newAssertionServer(t, okToken)
	auth := ClientAuthentication{Method: ClientAuthClientSecretBasic, ClientID: "c", ClientSecret: "s"}
	ctx := context.Background()
	details := json.RawMessage(`[{"type":"payment"}]`)

	if _, err := ClientCredentialsWithDetails(ctx, s.URL, auth, ssrf.DevModeFetchSettings(), nil, nil, details, nil); err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := s.forms[0].Get("authorization_details"); got != string(details) {
		t.Errorf("form = %q", got)
	}
	if _, err := ClientCredentialsWithDetails(ctx, s.URL, auth, ssrf.DevModeFetchSettings(), nil, nil, json.RawMessage(`{"a":1}`), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("object: err = %v, want ErrInvalidRequest", err)
	}
}

func TestJWTBearer_A28_A29(t *testing.T) {
	s := newAssertionServer(t, okToken)
	auth := ClientAuthentication{Method: ClientAuthClientSecretBasic, ClientID: "c", ClientSecret: "s"}
	ctx := context.Background()

	if _, err := JWTBearer(ctx, s.URL, auth, ssrf.DevModeFetchSettings(), JWTBearerInput{Assertion: "jag", Scopes: []string{"read"}, Resources: []string{"https://r"}}, nil); err != nil {
		t.Fatalf("err = %v", err)
	}
	f := s.forms[0]
	if f.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || f.Get("assertion") != "jag" || f.Get("scope") != "read" || f.Get("resource") != "https://r" {
		t.Errorf("form = %v", f)
	}

	if _, err := JWTBearer(ctx, s.URL, auth, ssrf.DevModeFetchSettings(), JWTBearerInput{}, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("empty assertion: err = %v", err)
	}
	if len(s.forms) != 1 {
		t.Errorf("requests = %d, an empty assertion must send nothing", len(s.forms))
	}
}
