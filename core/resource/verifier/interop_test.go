package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	interopIssuer   = "https://as.example.com"
	interopAudience = "https://api.example.com/mcp"
	interopKID      = "interop-kid"
	entraAudience   = "6e74172b-be56-4843-9ff4-e66a39bb12e3"
)

type interopVerifier struct {
	key *ecdsa.PrivateKey
	jc  *verifier.JWKSCache
}

func newInterop(t *testing.T) *interopVerifier {
	t.Helper()
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwks, err := testutil.BuildJWKSWithKID(&key.PublicKey, interopKID)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn:    func(context.Context) ([]byte, map[string][]string, error) { return jwks, nil, nil },
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)
	return &interopVerifier{key: key, jc: jc}
}

func (i *interopVerifier) verifier(t *testing.T, opts ...verifier.Option) *verifier.TokenVerifier {
	t.Helper()
	v, err := verifier.NewTokenVerifier(interopIssuer, interopAudience, i.jc, opts...)
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	return v
}

// sign builds a token with the given typ header ("" leaves it out) and claims merged
// over iss, sub, aud and exp.
func (i *interopVerifier) sign(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	return signWithKID(t, i.key, interopKID, typ, claims)
}

func signWithKID(t *testing.T, key *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	base := map[string]any{
		"iss": interopIssuer,
		"sub": "user-1",
		"aud": interopAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, val := range claims {
		if val == nil {
			delete(base, k)
			continue
		}
		base[k] = val
	}
	signerOpts := &jose.SignerOptions{}
	if typ != "" {
		signerOpts = signerOpts.WithType(jose.ContentType(typ))
	}
	signingKey := jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}
	signer, err := jose.NewSigner(signingKey, signerOpts)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	token, err := jwt.Signed(signer).Claims(base).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return token
}

func fullClaims(extra map[string]any) map[string]any {
	out := map[string]any{"iat": time.Now().Unix(), "jti": "j1", "client_id": "client-1"}
	for k, val := range extra {
		out[k] = val
	}
	return out
}

func TestTokenTypes_A1_A2_A3_A74(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	def := i.verifier(t)
	withJWT := i.verifier(t, verifier.WithAcceptedTokenTypes("at+jwt", "JWT"))
	withNone := i.verifier(t, verifier.WithAcceptedTokenTypes(verifier.TokenTypeNone))

	for _, tt := range []struct {
		name    string
		v       *verifier.TokenVerifier
		typ     string
		wantErr bool
	}{
		{"default at+jwt", def, "at+jwt", false},
		{"default application/at+jwt", def, "application/at+jwt", false},
		{"default upper case", def, "AT+JWT", false},
		{"default refuses JWT", def, "JWT", true},
		{"default refuses a leading space", def, " at+jwt", true},
		{"default refuses a trailing space", def, "at+jwt ", true},
		{"default refuses no typ", def, "", true},
		{"option accepts JWT", withJWT, "JWT", false},
		{"option accepts application/jwt", withJWT, "application/jwt", false},
		{"option still refuses dpop+jwt", withJWT, "dpop+jwt", true},
		{"none accepts no typ", withNone, "", false},
		{"none refuses a literal none", withNone, "none", true},
		{"none refuses at+jwt", withNone, "at+jwt", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.v.VerifyToken(ctx, i.sign(t, tt.typ, fullClaims(nil)), nil)
			if tt.wantErr && !errors.Is(err, verifier.ErrInvalidClaims) {
				t.Errorf("err = %v, want ErrInvalidClaims", err)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("err = %v, want accepted", err)
			}
		})
	}
}

func TestOptionValidation_A2_A74_A75(t *testing.T) {
	i := newInterop(t)
	for name, opt := range map[string]verifier.Option{
		"no types":        verifier.WithAcceptedTokenTypes(),
		"empty type":      verifier.WithAcceptedTokenTypes(""),
		"prefix only":     verifier.WithAcceptedTokenTypes("application/"),
		"no required":     verifier.WithRequiredClaims(),
		"blank required":  verifier.WithRequiredClaims(" "),
		"no scope claims": verifier.WithScopeClaims(),
		"no clients":      verifier.WithClientClaims(),
		"no markers":      verifier.WithAccessTokenMarkers(),
		"empty audience":  verifier.WithExpectedAudience(" "),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.NewTokenVerifier(interopIssuer, interopAudience, i.jc, opt); err == nil {
				t.Error("want an option error")
			}
		})
	}
}

func TestIDTokenGuard_A4_A5_A83(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	v := i.verifier(t, verifier.WithAcceptedTokenTypes("at+jwt", "JWT"))

	for name, extra := range map[string]map[string]any{
		"nonce":          {"nonce": "n"},
		"at_hash":        {"at_hash": "h"},
		"c_hash":         {"c_hash": "h"},
		"payload typ ID": {"typ": "ID"},
		"payload typ 5":  {"typ": 5},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyToken(ctx, i.sign(t, "JWT", fullClaims(extra)), nil)
			if !errors.Is(err, verifier.ErrInvalidClaims) {
				t.Errorf("typ JWT: err = %v, want ErrInvalidClaims", err)
			}
			if _, err := v.VerifyToken(ctx, i.sign(t, "at+jwt", fullClaims(extra)), nil); err != nil {
				t.Errorf("typ at+jwt: err = %v, want accepted as in v0.4.0", err)
			}
		})
	}

	t.Run("payload typ Bearer passes", func(t *testing.T) {
		if _, err := v.VerifyToken(ctx, i.sign(t, "JWT", fullClaims(map[string]any{"typ": "Bearer"})), nil); err != nil {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("code-flow ID token has no marker", func(t *testing.T) {
		oidc := i.verifier(t,
			verifier.WithAcceptedTokenTypes("JWT"),
			verifier.WithClientClaims("azp"),
			verifier.WithRequiredClaims("iat"),
		)
		token := i.sign(t, "JWT", map[string]any{"iat": time.Now().Unix(), "azp": "client-1", "name": "A"})
		if _, err := oidc.VerifyToken(ctx, token, nil); !errors.Is(err, verifier.ErrInvalidClaims) {
			t.Errorf("err = %v, want ErrInvalidClaims", err)
		}
	})

	t.Run("markers replace the default list", func(t *testing.T) {
		entra := i.verifier(t,
			verifier.WithAcceptedTokenTypes("JWT"),
			verifier.WithScopeClaims("scp", "roles"),
			verifier.WithClientClaims("azp"),
			verifier.WithRequiredClaims("iat", "tid"),
			verifier.WithAccessTokenMarkers("scp", "azpacr", "appidacr"),
		)
		idToken := i.sign(t, "JWT", map[string]any{"iat": time.Now().Unix(), "tid": "t", "azp": "c", "roles": []any{"admin"}})
		if _, err := entra.VerifyToken(ctx, idToken, nil); !errors.Is(err, verifier.ErrInvalidClaims) {
			t.Errorf("ID token with roles: err = %v, want ErrInvalidClaims", err)
		}
		app := i.sign(t, "JWT", map[string]any{"iat": time.Now().Unix(), "tid": "t", "azp": "c", "azpacr": "1"})
		if _, err := entra.VerifyToken(ctx, app, nil); err != nil {
			t.Errorf("app token: err = %v, want accepted", err)
		}
	})

	t.Run("azp alone is refused by default", func(t *testing.T) {
		d := i.verifier(t, verifier.WithAcceptedTokenTypes("JWT"), verifier.WithClientClaims("azp"), verifier.WithRequiredClaims("iat"))
		token := i.sign(t, "JWT", map[string]any{"iat": time.Now().Unix(), "azp": "c"})
		if _, err := d.VerifyToken(ctx, token, nil); !errors.Is(err, verifier.ErrInvalidClaims) {
			t.Errorf("err = %v, want ErrInvalidClaims", err)
		}
	})
}

func TestRequiredClaims_A6_A7_A75(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	subOnly := i.verifier(t, verifier.WithRequiredClaims("sub"))
	tid := i.verifier(t, verifier.WithRequiredClaims("tid"))
	def := i.verifier(t)

	for _, tt := range []struct {
		name    string
		v       *verifier.TokenVerifier
		claims  map[string]any
		wantErr bool
	}{
		{"relaxed: no jti, iat or client_id", subOnly, nil, false},
		{"relaxed: exp still required", subOnly, map[string]any{"exp": nil}, true},
		{"relaxed: sub still required", subOnly, map[string]any{"sub": nil}, true},
		{"relaxed: iss still required", subOnly, map[string]any{"iss": nil}, true},
		{"relaxed: aud still required", subOnly, map[string]any{"aud": nil}, true},
		{"default: no jti", def, map[string]any{"iat": time.Now().Unix(), "client_id": "c"}, true},
		{"default: no client_id", def, map[string]any{"iat": time.Now().Unix(), "jti": "j"}, true},
		{"tid present", tid, map[string]any{"tid": "t"}, false},
		{"tid empty", tid, map[string]any{"tid": ""}, true},
		{"tid missing", tid, nil, true},
		{"tid null", tid, map[string]any{"tid": json.RawMessage("null")}, true},
		{"default: numeric jti", def, map[string]any{"iat": time.Now().Unix(), "jti": 5, "client_id": "c"}, true},
		{"default: boolean jti", def, map[string]any{"iat": time.Now().Unix(), "jti": true, "client_id": "c"}, true},
		{"default: numeric client_id", def, map[string]any{"iat": time.Now().Unix(), "jti": "j", "client_id": 5}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.v.VerifyToken(ctx, i.sign(t, "at+jwt", tt.claims), nil)
			if tt.wantErr && !errors.Is(err, verifier.ErrInvalidClaims) {
				t.Errorf("err = %v, want ErrInvalidClaims", err)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("err = %v, want accepted", err)
			}
		})
	}
}

func TestScopeClaims_A8_A9(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	v := i.verifier(t, verifier.WithScopeClaims("scp", "roles"), verifier.WithRequiredClaims("sub"))

	claims, err := v.VerifyToken(ctx, i.sign(t, "at+jwt", map[string]any{"scp": "a b", "roles": []any{"c", "a"}}), nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	got := claims.Scopes()
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("scopes = %v, want a b c", got)
	}
	if err := claims.RequireScope("c"); err != nil {
		t.Errorf("RequireScope: %v", err)
	}

	for name, bad := range map[string]any{"number": 5, "bool": true, "mixed array": []any{"a", 1}} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.VerifyToken(ctx, i.sign(t, "at+jwt", map[string]any{"scp": bad}), nil); !errors.Is(err, verifier.ErrInvalidClaims) {
				t.Errorf("err = %v, want ErrInvalidClaims", err)
			}
		})
	}

	t.Run("default ignores a bad scope shape, as in v0.4.0", func(t *testing.T) {
		d := i.verifier(t)
		c, err := d.VerifyToken(ctx, i.sign(t, "at+jwt", fullClaims(map[string]any{"scope": 5})), nil)
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if len(c.Scopes()) != 0 {
			t.Errorf("scopes = %v, want none", c.Scopes())
		}
	})
}

func TestClientClaims_A10_A11(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()

	v := i.verifier(t, verifier.WithClientClaims("cid", "azp"), verifier.WithRequiredClaims("sub"))
	c, err := v.VerifyToken(ctx, i.sign(t, "at+jwt", map[string]any{"azp": "from-azp"}), nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if c.ClientID() != "from-azp" {
		t.Errorf("ClientID = %q", c.ClientID())
	}

	strict := i.verifier(t, verifier.WithClientClaims("cid"))
	if _, err := strict.VerifyToken(ctx, i.sign(t, "at+jwt", map[string]any{"iat": time.Now().Unix(), "jti": "j"}), nil); !errors.Is(err, verifier.ErrInvalidClaims) {
		t.Errorf("no cid or client_id: err = %v, want ErrInvalidClaims", err)
	}
	c, err = strict.VerifyToken(ctx, i.sign(t, "at+jwt", fullClaims(nil)), nil)
	if err != nil {
		t.Fatalf("client_id only: err = %v", err)
	}
	if c.ClientID() != "" {
		t.Errorf("ClientID = %q, want empty", c.ClientID())
	}
}

func TestExpectedAudience_A12_A13(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	v := i.verifier(t, verifier.WithExpectedAudience(entraAudience))

	if _, err := v.VerifyToken(ctx, i.sign(t, "at+jwt", fullClaims(map[string]any{"aud": entraAudience})), nil); err != nil {
		t.Errorf("GUID aud: err = %v", err)
	}
	if _, err := v.VerifyToken(ctx, i.sign(t, "at+jwt", fullClaims(nil)), nil); !errors.Is(err, verifier.ErrAudienceMismatch) {
		t.Errorf("resource aud: err = %v, want ErrAudienceMismatch", err)
	}
}

func TestKeyMatching_A14_A15(t *testing.T) {
	ctx := context.Background()
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rsaKey, err := testutil.GenerateRS256Key()
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	build := func(keys ...jose.JSONWebKey) *verifier.TokenVerifier {
		data, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
			FetchFn:    func(context.Context) ([]byte, map[string][]string, error) { return data, nil, nil },
			DefaultTTL: time.Hour,
		})
		t.Cleanup(jc.Close)
		v, err := verifier.NewTokenVerifier(interopIssuer, interopAudience, jc)
		if err != nil {
			t.Fatalf("verifier: %v", err)
		}
		return v
	}
	token := signWithKID(t, key, interopKID, "at+jwt", fullClaims(nil))

	t.Run("no alg, right type", func(t *testing.T) {
		v := build(jose.JSONWebKey{Key: &key.PublicKey, KeyID: interopKID})
		if _, err := v.VerifyToken(ctx, token, nil); err != nil {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("use enc never matches", func(t *testing.T) {
		v := build(jose.JSONWebKey{Key: &key.PublicKey, KeyID: interopKID, Use: "enc"})
		if _, err := v.VerifyToken(ctx, token, nil); err == nil {
			t.Error("want refusal")
		}
	})
	t.Run("no alg, wrong type", func(t *testing.T) {
		v := build(jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: interopKID})
		if _, err := v.VerifyToken(ctx, token, nil); !errors.Is(err, verifier.ErrInvalidClaims) {
			t.Errorf("err = %v, want no key found rather than a failed signature", err)
		}
	})
	t.Run("alg mismatch still refused", func(t *testing.T) {
		v := build(jose.JSONWebKey{Key: &key.PublicKey, KeyID: interopKID, Algorithm: "ES384"})
		if _, err := v.VerifyToken(ctx, token, nil); err == nil {
			t.Error("want refusal")
		}
	})
	t.Run("token with no kid refused", func(t *testing.T) {
		v := build(jose.JSONWebKey{Key: &key.PublicKey})
		noKID := signWithKID(t, key, "", "at+jwt", fullClaims(nil))
		if _, err := v.VerifyToken(ctx, noKID, nil); !errors.Is(err, verifier.ErrInvalidClaims) {
			t.Errorf("err = %v, want ErrInvalidClaims", err)
		}
	})
}

// TestServerShapes checks tokens shaped like those of other servers with the options
// a consumer sets for them, and that the defaults still refuse them.
func TestServerShapes_A72_A73(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	now := time.Now().Unix()

	for _, tt := range []struct {
		name    string
		opts    []verifier.Option
		typ     string
		access  map[string]any
		idToken map[string]any
		scope   string
		client  string
	}{
		{
			name: "keycloak",
			opts: []verifier.Option{
				verifier.WithAcceptedTokenTypes("at+jwt", "JWT"),
				verifier.WithClientClaims("azp", "client_id"),
				verifier.WithRequiredClaims("iat"),
			},
			typ:     "JWT",
			access:  map[string]any{"iat": now, "azp": "app", "scope": "crm:read", "typ": "Bearer", "aud": []any{interopAudience, "account"}},
			idToken: map[string]any{"iat": now, "azp": "app", "typ": "ID"},
			scope:   "crm:read", client: "app",
		},
		{
			name: "entra",
			opts: []verifier.Option{
				verifier.WithAcceptedTokenTypes("JWT"),
				verifier.WithExpectedAudience(entraAudience),
				verifier.WithScopeClaims("scp", "roles"),
				verifier.WithClientClaims("azp", "appid"),
				verifier.WithRequiredClaims("iat", "tid"),
				verifier.WithAccessTokenMarkers("scp", "azpacr", "appidacr"),
			},
			typ:     "JWT",
			access:  map[string]any{"iat": now, "tid": "t", "aud": entraAudience, "azp": "app", "azpacr": "1", "scp": "crm:read crm:write", "roles": []any{"admin"}},
			idToken: map[string]any{"iat": now, "tid": "t", "aud": entraAudience, "azp": "app", "roles": []any{"admin"}},
			scope:   "admin", client: "app",
		},
		{
			name: "okta",
			opts: []verifier.Option{
				verifier.WithAcceptedTokenTypes("at+jwt", "JWT", verifier.TokenTypeNone),
				verifier.WithScopeClaims("scp", "scope"),
				verifier.WithClientClaims("cid", "client_id"),
				verifier.WithRequiredClaims("iat", "jti"),
			},
			typ:     "",
			access:  map[string]any{"iat": now, "jti": "j", "cid": "app", "scp": []any{"a", "b"}},
			idToken: map[string]any{"iat": now, "jti": "j", "nonce": "n"},
			scope:   "b", client: "app",
		},
		{
			name: "auth0",
			opts: []verifier.Option{
				verifier.WithAcceptedTokenTypes("at+jwt", "JWT"),
				verifier.WithScopeClaims("scope", "permissions"),
				verifier.WithClientClaims("azp", "client_id"),
				verifier.WithRequiredClaims("iat"),
			},
			typ:     "JWT",
			access:  map[string]any{"iat": now, "azp": "app", "scope": "read", "permissions": []any{"write"}, "aud": []any{interopAudience, interopIssuer + "/userinfo"}},
			idToken: map[string]any{"iat": now, "azp": "app"},
			scope:   "write", client: "app",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := i.verifier(t, tt.opts...)
			claims, err := v.VerifyToken(ctx, i.sign(t, tt.typ, tt.access), nil)
			if err != nil {
				t.Fatalf("access token: %v", err)
			}
			if err := claims.RequireScope(tt.scope); err != nil {
				t.Errorf("RequireScope(%q): %v", tt.scope, err)
			}
			if claims.ClientID() != tt.client {
				t.Errorf("ClientID = %q, want %q", claims.ClientID(), tt.client)
			}
			if _, err := v.VerifyToken(ctx, i.sign(t, tt.typ, tt.idToken), nil); !errors.Is(err, verifier.ErrInvalidClaims) {
				t.Errorf("ID token: err = %v, want ErrInvalidClaims", err)
			}
			if _, err := i.verifier(t).VerifyToken(ctx, i.sign(t, tt.typ, tt.access), nil); err == nil {
				t.Error("default verifier accepted the shape")
			}
		})
	}
}

func TestAuthorizationDetailsClaim_A26_A27(t *testing.T) {
	i := newInterop(t)
	v := i.verifier(t)
	ctx := context.Background()
	c, err := v.VerifyToken(ctx, i.sign(t, "at+jwt", fullClaims(map[string]any{"authorization_details": []any{map[string]any{"type": "payment"}}})), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(c.AuthorizationDetails()); got != `[{"type":"payment"}]` {
		t.Errorf("AuthorizationDetails = %s", got)
	}
	c, err = v.VerifyToken(ctx, i.sign(t, "at+jwt", fullClaims(nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.AuthorizationDetails() != nil {
		t.Error("want nil with no claim")
	}
}

func TestScopeImplication_A59_A60(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	token := i.sign(t, "at+jwt", fullClaims(map[string]any{"scope": "write"}))

	exact, err := i.verifier(t).VerifyToken(ctx, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if exact.HasScope("read") {
		t.Error("no implication: write must not satisfy read")
	}

	v := i.verifier(t, verifier.WithScopeImplication(func(granted, required string) bool {
		return granted == "write" && required == "read"
	}))
	claims, err := v.VerifyToken(ctx, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := claims.RequireScope("read"); err != nil {
		t.Errorf("implied scope: %v", err)
	}
	if claims.HasScope("admin") {
		t.Error("an unrelated scope must not pass")
	}
}
