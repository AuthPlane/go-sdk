package authplane

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/internal/metadata"
	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

// tokenMode selects what the fake token endpoint answers.
const (
	tokenServerError int32 = iota
	tokenInvalidScope
	tokenOK
)

type breakerAS struct {
	srv         *httptest.Server
	tokenMode   atomic.Int32
	tokenCalls  atomic.Int32
	introspects atomic.Int32
}

func newBreakerAS(t *testing.T) *breakerAS {
	t.Helper()
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwks, err := testutil.BuildJWKSWithKID(&key.PublicKey, "test-kid")
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}
	as := &breakerAS{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 as.srv.URL,
			"token_endpoint":         as.srv.URL + "/token",
			"jwks_uri":               as.srv.URL + "/jwks",
			"introspection_endpoint": as.srv.URL + "/introspect",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		as.tokenCalls.Add(1)
		switch as.tokenMode.Load() {
		case tokenServerError:
			w.WriteHeader(http.StatusInternalServerError)
		case tokenInvalidScope:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_scope"}`))
		default:
			_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer","expires_in":1}`))
		}
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, _ *http.Request) {
		as.introspects.Add(1)
		_, _ = w.Write([]byte(`{"active":true}`))
	})
	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

func (as *breakerAS) client(t *testing.T, threshold int, cooldown time.Duration) *Client {
	t.Helper()
	c, err := NewClient(context.Background(), as.srv.URL,
		WithClientCredentials("id", "secret"),
		WithFetchSettings(DevModeFetchSettings()),
		WithCircuitBreaker(threshold, cooldown),
		WithTokenCacheTTLBuffer(time.Hour), // every call reaches the server
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestBreaker_ProbeWithPolicyAnswerCloses_A38(t *testing.T) {
	ctx := context.Background()
	as := newBreakerAS(t)
	c := as.client(t, 2, 20*time.Millisecond)

	for range 2 {
		_, _ = c.ClientCredentials(ctx, ClientCredentialsInput{})
	}
	if _, err := c.ClientCredentials(ctx, ClientCredentialsInput{}); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("after failures: err = %v, want ErrCircuitOpen", err)
	}
	time.Sleep(30 * time.Millisecond)

	as.tokenMode.Store(tokenInvalidScope)
	if _, err := c.ClientCredentials(ctx, ClientCredentialsInput{}); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("probe: err = %v, want ErrInvalidScope", err)
	}

	as.tokenMode.Store(tokenOK)
	if _, err := c.ClientCredentials(ctx, ClientCredentialsInput{}); err != nil {
		t.Fatalf("after probe: err = %v, want recovery", err)
	}
}

func TestBreaker_NeutralProbeReleasesSlot_A39(t *testing.T) {
	ctx := context.Background()
	as := newBreakerAS(t)
	c := as.client(t, 2, 20*time.Millisecond)

	for range 2 {
		_, _ = c.ClientCredentials(ctx, ClientCredentialsInput{})
	}
	time.Sleep(30 * time.Millisecond)

	// An empty subject token fails locally, so the probe learns nothing.
	if _, err := c.TokenExchange(ctx, TokenExchangeInput{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("probe: err = %v, want ErrInvalidRequest", err)
	}

	as.tokenMode.Store(tokenOK)
	if _, err := c.ClientCredentials(ctx, ClientCredentialsInput{}); err != nil {
		t.Fatalf("next probe: err = %v, want it to reach the server", err)
	}
}

func TestBreaker_CallerErrorsDoNotOpen_A39(t *testing.T) {
	ctx := context.Background()
	as := newBreakerAS(t)
	c := as.client(t, 2, time.Hour)
	as.tokenMode.Store(tokenOK)

	for range 5 {
		_, _ = c.TokenExchange(ctx, TokenExchangeInput{})
	}
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	for range 5 {
		_, _ = c.ClientCredentials(canceledCtx, ClientCredentialsInput{})
	}

	if _, err := c.ClientCredentials(ctx, ClientCredentialsInput{}); err != nil {
		t.Fatalf("err = %v, want the breaker still closed", err)
	}
}

func TestBreaker_IntrospectionSeparateFromToken_A77(t *testing.T) {
	ctx := context.Background()
	as := newBreakerAS(t)
	c := as.client(t, 2, time.Hour)

	for range 2 {
		_, _ = c.ClientCredentials(ctx, ClientCredentialsInput{})
	}
	if _, err := c.ClientCredentials(ctx, ClientCredentialsInput{}); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("token: err = %v, want ErrCircuitOpen", err)
	}

	resp, err := c.Introspect(ctx, "some-token")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active || as.introspects.Load() != 1 {
		t.Errorf("active = %v, introspects = %d; want the call to reach the server", resp.Active, as.introspects.Load())
	}
}

// Options through WithVerifierOptions must not drop the auto-wired checker.
func TestClientResource_VerifierOptionsKeepIntrospection_A34_A35_A41(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwks, err := testutil.BuildJWKSWithKID(&key.PublicKey, "test-kid")
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}
	var introspects atomic.Int32
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
			"introspection_endpoint": srv.URL + "/introspect",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) })
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, _ *http.Request) {
		introspects.Add(1)
		_, _ = w.Write([]byte(`{"active":false}`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	c, err := NewClient(ctx, srv.URL, WithClientCredentials("id", "secret"), WithFetchSettings(DevModeFetchSettings()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	const uri = "https://api.example.com/mcp"
	token, err := testutil.SignTokenWithClaims(key, jose.ES256, "test-kid", srv.URL, uri, "user", "client", nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	for name, opt := range map[string]verifier.Option{
		"clock skew":  verifier.WithClockSkew(time.Second),
		"fail closed": verifier.WithFailClosed(),
	} {
		t.Run(name, func(t *testing.T) {
			res, err := c.Resource(uri, resource.WithVerifierOptions(opt))
			if err != nil {
				t.Fatalf("Resource: %v", err)
			}
			if _, err := res.VerifyToken(ctx, token); !errors.Is(err, verifier.ErrTokenRevoked) {
				t.Errorf("err = %v, want ErrTokenRevoked", err)
			}
		})
	}

	t.Run("explicit checker wins", func(t *testing.T) {
		before := introspects.Load()
		res, err := c.Resource(uri, resource.WithVerifierOptions(verifier.WithRevocationChecker(verifier.NullRevocationChecker)))
		if err != nil {
			t.Fatalf("Resource: %v", err)
		}
		if _, err := res.VerifyToken(ctx, token); err != nil {
			t.Errorf("err = %v, want accepted", err)
		}
		if introspects.Load() != before {
			t.Error("introspection ran despite the explicit checker")
		}
	})
}

func TestClientMetadata_A16(t *testing.T) {
	as := newBreakerAS(t)
	c := as.client(t, 2, time.Hour)
	meta, err := c.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if meta.TokenEndpoint == "" || meta.Raw()["issuer"] != as.srv.URL {
		t.Errorf("meta = %+v", meta)
	}
}

func TestNewClient_HTTPIssuerNeedsSettings_A36(t *testing.T) {
	as := newBreakerAS(t)
	if _, err := NewClient(context.Background(), as.srv.URL); err == nil {
		t.Error("default settings: want an http issuer refused")
	}
}

func TestTokenCache_ExchangeBehavior_A22_A48(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	reply := atomic.Value{}
	reply.Store(`{"access_token":"a","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","expires_in":3600}`)
	var srv *httptest.Server
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := testutil.BuildJWKSWithKID(&key.PublicKey, "k")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(reply.Load().(string)))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()
	c, err := NewClient(ctx, srv.URL, WithClientCredentials("id", "secret"), WithFetchSettings(DevModeFetchSettings()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	t.Run("hit keeps issued_token_type", func(t *testing.T) {
		in := TokenExchangeInput{SubjectToken: "s1"}
		if _, err := c.TokenExchange(ctx, in); err != nil {
			t.Fatal(err)
		}
		before := calls.Load()
		resp, err := c.TokenExchange(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		if calls.Load() != before {
			t.Error("want a cache hit")
		}
		if resp.IssuedTokenType == "" {
			t.Error("cache hit lost issued_token_type")
		}
	})

	t.Run("N_A is not cached", func(t *testing.T) {
		reply.Store(`{"access_token":"jag","token_type":"N_A","issued_token_type":"urn:ietf:params:oauth:token-type:id-jag","expires_in":300}`)
		in := TokenExchangeInput{SubjectToken: "s2"}
		for range 2 {
			if _, err := c.TokenExchange(ctx, in); err != nil {
				t.Fatal(err)
			}
		}
		if n := calls.Load(); n != 3 {
			t.Errorf("calls = %d, want both N_A exchanges to reach the server", n)
		}
	})
}

func TestCacheKeys_DoNotCollideOrHoldTokens_A49(t *testing.T) {
	if clientCredentialsCacheKey(nil, []string{"a,b"}) == clientCredentialsCacheKey(nil, []string{"a", "b"}) {
		t.Error("one value containing a comma collided with two values")
	}
	if cacheKeyOf("ab", "c") == cacheKeyOf("a", "bc") {
		t.Error("parts must be length-prefixed")
	}
	if clientCredentialsCacheKey([]string{"a"}, nil) == clientCredentialsCacheKey(nil, []string{"a"}) {
		t.Error("a scope collided with a resource")
	}
	k := tokenExchangeCacheKey(TokenExchangeInput{SubjectToken: "secret-subject-token"})
	if strings.Contains(k, "secret-subject-token") {
		t.Error("the key holds the subject token")
	}
	if tokenExchangeCacheKey(TokenExchangeInput{SubjectToken: "a|b"}) == tokenExchangeCacheKey(TokenExchangeInput{SubjectToken: "a", SubjectTokenType: "b"}) {
		t.Error("delimiter collision")
	}
}

func TestClientPrivateKeyJWT_NoKeyFails_A25(t *testing.T) {
	as := newBreakerAS(t)
	_, err := NewClient(context.Background(), as.srv.URL,
		WithClientAuthentication(ClientAuthentication{Method: ClientAuthPrivateKeyJWT, ClientID: "c"}),
		WithFetchSettings(DevModeFetchSettings()))
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func noIntrospectionClient(t *testing.T) (*Client, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := testutil.BuildJWKSWithKID(&key.PublicKey, "k")
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer","expires_in":3600}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := NewClient(context.Background(), srv.URL, WithClientCredentials("id", "secret"),
		WithFetchSettings(DevModeFetchSettings()), WithCircuitBreaker(2, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, key, srv.URL
}

func TestNoIntrospectionEndpoint_A40(t *testing.T) {
	ctx := context.Background()
	const uri = "https://api.example.com/mcp"

	t.Run("fail open warns once, keeps the breaker closed", func(t *testing.T) {
		c, key, issuer := noIntrospectionClient(t)
		var logs bytes.Buffer
		old := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		defer slog.SetDefault(old)

		res, err := c.Resource(uri)
		if err != nil {
			t.Fatal(err)
		}
		token, err := testutil.SignTokenWithClaims(key, jose.ES256, "k", issuer, uri, "u", "c", nil)
		if err != nil {
			t.Fatal(err)
		}
		for range 5 {
			if _, err := res.VerifyToken(ctx, token); err != nil {
				t.Fatalf("err = %v", err)
			}
		}
		if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
			t.Errorf("warnings = %d, want 1:\n%s", n, logs.String())
		}
		if _, err := c.ClientCredentials(ctx, ClientCredentialsInput{}); err != nil {
			t.Errorf("token call: %v, want the breaker closed", err)
		}
	})

	t.Run("fail closed refuses every token", func(t *testing.T) {
		c, key, issuer := noIntrospectionClient(t)
		res, err := c.Resource(uri, resource.WithVerifierOptions(verifier.WithFailClosed()))
		if err != nil {
			t.Fatal(err)
		}
		token, err := testutil.SignTokenWithClaims(key, jose.ES256, "k", issuer, uri, "u", "c", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := res.VerifyToken(ctx, token); !errors.Is(err, verifier.ErrRevocationUnavailable) {
			t.Errorf("err = %v, want ErrRevocationUnavailable", err)
		}
	})
}

func TestUnsafeConsentURLDropped_A56(t *testing.T) {
	c := &Client{fetchSettings: DefaultFetchSettings().internal()}
	for rawURL, want := range map[string]string{
		"https://as.example.com/consent": "https://as.example.com/consent",
		"javascript:alert(1)":            "",
		"http://as.example.com/consent":  "",
		"https://":                       "",
	} {
		err := &ConsentRequiredError{ConsentURL: rawURL, Cause: ErrConsentRequired}
		c.dropUnsafeConsentURL(fmt.Errorf("wrapped: %w", err))
		if err.ConsentURL != want {
			t.Errorf("%q became %q, want %q", rawURL, err.ConsentURL, want)
		}
	}
}

func TestClientMetadata_Unavailable_A17(t *testing.T) {
	mc := metadata.New(metadata.Config{IssuerURL: "http://127.0.0.1:1", FetchSettings: DevModeFetchSettings().internal()})
	defer mc.Close()
	c := &Client{metadataCache: mc}
	if _, err := c.Metadata(context.Background()); !errors.Is(err, verifier.ErrMetadataUnavailable) {
		t.Errorf("err = %v, want ErrMetadataUnavailable", err)
	}
}

func TestClient_PrivateKeyJWTUsesIssuerAudience_A24(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := testutil.BuildJWKSWithKID(&key.PublicKey, "k")
	if err != nil {
		t.Fatal(err)
	}
	var assertion atomic.Value
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		assertion.Store(r.FormValue("client_assertion"))
		_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer","expires_in":3600}`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()
	ctx := context.Background()
	c, err := NewClient(ctx, srv.URL, WithFetchSettings(DevModeFetchSettings()), WithClientAuthentication(ClientAuthentication{
		Method: ClientAuthPrivateKeyJWT, ClientID: "client-1", SigningKey: key, SigningAlg: jose.ES256,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.ClientCredentials(ctx, ClientCredentialsInput{}); err != nil {
		t.Fatal(err)
	}
	claims, err := testutil.UnverifiedClaims(assertion.Load().(string))
	if err != nil {
		t.Fatal(err)
	}
	if claims["aud"] != srv.URL {
		t.Errorf("aud = %v, want the issuer", claims["aud"])
	}
}

func TestTokenExchange_DropsUnsafeConsentURL_A56(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := testutil.BuildJWKSWithKID(&key.PublicKey, "k")
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"consent_required","consent_url":"javascript:alert(1)"}`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()
	ctx := context.Background()
	c, err := NewClient(ctx, srv.URL, WithClientCredentials("id", "secret"), WithFetchSettings(DevModeFetchSettings()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, err = c.TokenExchange(ctx, TokenExchangeInput{SubjectToken: "s"})
	var consent *ConsentRequiredError
	if !errors.As(err, &consent) {
		t.Fatalf("err = %v", err)
	}
	if consent.ConsentURL != "" {
		t.Errorf("ConsentURL = %q", consent.ConsentURL)
	}
}

func TestNewClient_HonorsCallerContext_A54(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewClient(canceled, srv.URL, WithFetchSettings(DevModeFetchSettings())); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: err = %v", err)
	}

	short, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	start := time.Now()
	if _, err := NewClient(short, srv.URL, WithFetchSettings(DevModeFetchSettings())); err == nil {
		t.Error("deadline: want an error")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("took %v, want it to return at the caller's deadline", took)
	}
}

func TestNewClient_NegativeMaxStale(t *testing.T) {
	as := newBreakerAS(t)
	if _, err := NewClient(context.Background(), as.srv.URL, WithFetchSettings(DevModeFetchSettings()), WithJWKSMaxStale(-time.Second)); err == nil {
		t.Error("want an error")
	}
}

func TestBreaker_DNSFailureDoesNotOpen_A39(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := testutil.BuildJWKSWithKID(&key.PublicKey, "k")
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "token_endpoint": "http://nonexistent.invalid/token", "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) })
	srv = httptest.NewServer(mux)
	defer srv.Close()
	ctx := context.Background()
	c, err := NewClient(ctx, srv.URL, WithClientCredentials("id", "secret"), WithFetchSettings(DevModeFetchSettings()), WithCircuitBreaker(2, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for range 4 {
		if _, err := c.ClientCredentials(ctx, ClientCredentialsInput{}); errors.Is(err, ErrCircuitOpen) {
			t.Fatal("a DNS failure opened the breaker")
		}
	}
}
