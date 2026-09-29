package conformancetests

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/internal/cache"
	"github.com/authplane/go-sdk/core/internal/metadata"
	"github.com/authplane/go-sdk/core/internal/ssrf"
	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

// helper: create a test server that serves AS metadata JSON.
func metadataServer(t *testing.T, meta map[string]any) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// helper: create a test server whose metadata includes ts.URL as the issuer.
func metadataServerDynamic(t *testing.T, buildMeta func(issuer string) map[string]any) *httptest.Server {
	t.Helper()
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(buildMeta(ts.URL))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestRFC8414MetadataIssuerMustMatchConfiguredIssuer(t *testing.T) {
	Case(t, "rfc8414-metadata-issuer-must-match-configured-issuer")
	ctx := context.Background()

	ts := metadataServer(t, map[string]any{
		"issuer":   "https://wrong-issuer.example.com",
		"jwks_uri": "https://auth.example.com/jwks",
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when metadata issuer does not match configured issuer")
	}
	if !strings.Contains(err.Error(), "issuer mismatch") {
		t.Errorf("expected issuer mismatch error, got: %v", err)
	}

	// Catalog variant: §3.3 requires the advertised issuer to be *identical*,
	// and §4 spells the comparison out as code-point-for-code-point. A metadata
	// issuer differing from the configured one only by a terminating slash is
	// therefore also a mismatch — this is the case a normalizing comparison
	// would silently accept, binding the client to a different identity.
	slashTS := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":   issuer + "/",
			"jwks_uri": issuer + "/jwks",
		}
	})

	slashMC := metadata.New(metadata.Config{
		IssuerURL:     slashTS.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer slashMC.Close()

	_, err = slashMC.Get(ctx)
	if err == nil {
		t.Fatal("expected error when the metadata issuer differs only by a terminating slash")
	}
	if !strings.Contains(err.Error(), "issuer mismatch") {
		t.Errorf("expected issuer mismatch error, got: %v", err)
	}
}

func TestRFC8414JWKSURIRequiredForJWTValidation(t *testing.T) {
	Case(t, "rfc8414-jwks-uri-required-for-jwt-validation")
	ctx := context.Background()

	// Metadata without jwks_uri.
	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":         issuer,
			"token_endpoint": "https://auth.example.com/token",
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	// Attempt to get the JWKS URI for JWT validation — should reject because
	// jwks_uri is missing from the metadata.
	jwksURI, err := mc.GetJWKSURI(ctx)
	if err != nil {
		// Implementation rejects at fetch time — satisfies catalog requirement.
		if !strings.Contains(err.Error(), "jwks_uri") {
			t.Errorf("expected error mentioning jwks_uri, got: %v", err)
		}
		return
	}
	// If no error, the JWKS URI must be empty, meaning JWT validation cannot proceed.
	if jwksURI != "" {
		t.Fatal("expected empty jwks_uri when not present in metadata")
	}
	// The SDK returns an empty string without error — the catalog requires rejection.
	// Attempting JWT validation without a JWKS URI would fail downstream, but the
	// metadata layer itself doesn't reject. Report the gap.
	t.Error("expected rejection (error) when jwks_uri is missing from metadata, but GetJWKSURI returned empty string without error")
}

func TestRFC8414MetadataMustContainIssuer(t *testing.T) {
	Case(t, "rfc8414-metadata-must-contain-issuer")
	ctx := context.Background()

	// Metadata without issuer field.
	ts := metadataServer(t, map[string]any{
		"jwks_uri": "https://auth.example.com/jwks",
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when issuer is missing from metadata")
	}
	if !strings.Contains(err.Error(), "missing required field") {
		t.Errorf("expected missing required field error, got: %v", err)
	}
}

func TestRFC8414DiscoveryURLMustInsertWellKnownBeforeIssuerPath(t *testing.T) {
	Case(t, "rfc8414-discovery-url-must-insert-well-known-before-issuer-path")
	ctx := context.Background()

	var serverURL string
	var requested []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server/tenant-a":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":   serverURL + "/tenant-a",
				"jwks_uri": "https://auth.example.com/jwks",
			})
		case "/tenant-a/.well-known/oauth-authorization-server":
			t.Fatalf("discovery used appended path form %q; expected well-known path before tenant path", r.URL.Path)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL + "/tenant-a",
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	meta, err := mc.Get(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Issuer != ts.URL+"/tenant-a" {
		t.Fatalf("issuer = %q, want %q", meta.Issuer, ts.URL+"/tenant-a")
	}
	if got := strings.Join(requested, ","); !strings.Contains(got, "/.well-known/oauth-authorization-server/tenant-a") {
		t.Fatalf("expected RFC 8414 path-based discovery request, got %s", got)
	}
}

func TestRFC8414JWKSURIMustBeAbsoluteHTTPSURL(t *testing.T) {
	Case(t, "rfc8414-jwks-uri-must-be-absolute-https-url")
	ctx := context.Background()

	// JWKS URI is relative (not absolute HTTPS) — must be rejected.
	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":   issuer,
			"jwks_uri": "/relative/jwks",
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DefaultFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when jwks_uri is not an absolute HTTPS URL")
	}
	if !strings.Contains(err.Error(), "jwks_uri") {
		t.Errorf("expected error mentioning jwks_uri, got: %v", err)
	}
}

func TestRFC8414TokenEndpointRequiredWhenTokenOperationIsUsed(t *testing.T) {
	Case(t, "rfc8414-token-endpoint-required-when-token-operation-is-used")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":   issuer,
			"jwks_uri": "https://auth.example.com/jwks",
			// token_endpoint omitted
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	// Fetch the token endpoint from metadata — should be empty.
	tokenEndpoint, err := mc.GetTokenEndpoint(ctx)
	if err != nil {
		// Implementation rejects at fetch time — satisfies catalog requirement.
		if !strings.Contains(err.Error(), "token_endpoint") {
			t.Errorf("expected error mentioning token_endpoint, got: %v", err)
		}
		return
	}

	// Attempt a token operation using the (empty) endpoint — must fail.
	_, err = testClientCredentials(ctx, tokenEndpoint, "test-client", "test-secret", []string{"read"}, nil)
	if err == nil {
		t.Fatal("expected error when attempting token operation without token_endpoint in metadata")
	}
	if !strings.Contains(err.Error(), "token_endpoint") && !strings.Contains(err.Error(), "unsupported protocol") && !strings.Contains(err.Error(), "empty url") && !strings.Contains(err.Error(), "no Host") {
		t.Logf("token operation rejected with: %v", err)
	}
}

func TestRFC8414TokenEndpointMustBeAbsoluteHTTPSURL(t *testing.T) {
	Case(t, "rfc8414-token-endpoint-must-be-absolute-https-url")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":         issuer,
			"jwks_uri":       "https://auth.example.com/jwks",
			"token_endpoint": "http://auth.example.com/oauth/token",
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DefaultFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when token_endpoint is not an absolute HTTPS URL")
	}
	if !strings.Contains(err.Error(), "token_endpoint") {
		t.Errorf("expected error mentioning token_endpoint, got: %v", err)
	}
}

func TestRFC8414IntrospectionEndpointMustBeAbsoluteHTTPSURL(t *testing.T) {
	Case(t, "rfc8414-introspection-endpoint-must-be-absolute-https-url")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":                 issuer,
			"jwks_uri":               "https://auth.example.com/jwks",
			"introspection_endpoint": "http://auth.example.com/oauth/introspect",
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DefaultFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when introspection_endpoint is not an absolute HTTPS URL")
	}
	if !strings.Contains(err.Error(), "introspection_endpoint") {
		t.Errorf("expected error mentioning introspection_endpoint, got: %v", err)
	}
}

func TestRFC8414RevocationEndpointMustBeAbsoluteHTTPSURL(t *testing.T) {
	Case(t, "rfc8414-revocation-endpoint-must-be-absolute-https-url")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":              issuer,
			"jwks_uri":            "https://auth.example.com/jwks",
			"revocation_endpoint": "http://auth.example.com/oauth/revoke",
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DefaultFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when revocation_endpoint is not an absolute HTTPS URL")
	}
	if !strings.Contains(err.Error(), "revocation_endpoint") {
		t.Errorf("expected error mentioning revocation_endpoint, got: %v", err)
	}
}

func TestRFC8414IntrospectionEndpointRequiredWhenIntrospectionIsUsed(t *testing.T) {
	Case(t, "rfc8414-introspection-endpoint-required-when-introspection-is-used")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":   issuer,
			"jwks_uri": "https://auth.example.com/jwks",
			// introspection_endpoint omitted
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	// Fetch the introspection endpoint from metadata — should be empty.
	introspectionEndpoint, err := mc.GetIntrospectionEndpoint(ctx)
	if err != nil {
		// Implementation rejects at fetch time — satisfies catalog requirement.
		if !strings.Contains(err.Error(), "introspection_endpoint") {
			t.Errorf("expected error mentioning introspection_endpoint, got: %v", err)
		}
		return
	}

	// Attempt an introspection operation using the (empty) endpoint — must fail.
	_, err = testIntrospect(ctx, introspectionEndpoint, "test-client", "test-secret", "some-token")
	if err == nil {
		t.Fatal("expected error when attempting introspection without introspection_endpoint in metadata")
	}
	if !strings.Contains(err.Error(), "introspection_endpoint") && !strings.Contains(err.Error(), "unsupported protocol") && !strings.Contains(err.Error(), "empty url") && !strings.Contains(err.Error(), "no Host") {
		t.Logf("introspection operation rejected with: %v", err)
	}
}

func TestRFC8414RevocationEndpointRequiredWhenRevocationIsUsed(t *testing.T) {
	Case(t, "rfc8414-revocation-endpoint-required-when-revocation-is-used")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":   issuer,
			"jwks_uri": "https://auth.example.com/jwks",
			// revocation_endpoint omitted
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	// Fetch the revocation endpoint from metadata — should be empty.
	revocationEndpoint, err := mc.GetRevocationEndpoint(ctx)
	if err != nil {
		// Implementation rejects at fetch time — satisfies catalog requirement.
		if !strings.Contains(err.Error(), "revocation_endpoint") {
			t.Errorf("expected error mentioning revocation_endpoint, got: %v", err)
		}
		return
	}

	// Attempt a revocation operation using the (empty) endpoint — must fail.
	err = testRevoke(ctx, revocationEndpoint, "test-client", "test-secret", "some-token")
	if err == nil {
		t.Fatal("expected error when attempting revocation without revocation_endpoint in metadata")
	}
	if !strings.Contains(err.Error(), "revocation_endpoint") && !strings.Contains(err.Error(), "unsupported protocol") && !strings.Contains(err.Error(), "empty url") && !strings.Contains(err.Error(), "no Host") {
		t.Logf("revocation operation rejected with: %v", err)
	}
}

// ---------------------------------------------------------------------------
// jwks_uri rotation
// ---------------------------------------------------------------------------

// rotationKID is the key id published on *both* of the rotating authorization
// server's key sets.
//
// One kid across the withdrawn and the rotated document is what gives the
// rotation case its edge. With two distinct kids, a token signed by the new
// key presents a kid the cached key set does not hold; that miss escalates
// into a forced JWKS re-fetch, which resolves jwks_uri again and lands on the
// rotated document. The token then verifies whether or not the interval-driven
// rebind ever happened, and the case reports a pass having measured the
// unknown-kid path instead of the one it is about. Under a single kid a cache
// still bound to the withdrawn URI finds a usable key, never escalates, and
// fails on the *signature* — so only a real rebind can turn the rejection into
// an acceptance. TestRFC8414RotationControlSameKIDBlocksTheKIDMissShortcut
// measures both halves of that claim.
const rotationKID = "as-signing-key"

// rotatingAS is an authorization server that publishes its signing key at one
// of two jwks_uri values and can be switched from the first to the second.
//
// Both JWKS documents are served by this server, and every request to the
// three paths is counted. That is what makes the case's side effects
// observable: jwks_uri values pointing at some other host are never fetched by
// the test's own client, so clauses about which document was fetched, and
// about the withdrawn one no longer being fetched, could not be checked at all.
type rotatingAS struct {
	// issuer is the server's base URL, and doubles as the metadata "issuer"
	// value — RFC 8414 §3.3 requires the two to be identical.
	issuer string

	rotated atomic.Bool

	metadataReads atomic.Int32
	v1Reads       atomic.Int32
	v2Reads       atomic.Int32
}

// newRotatingAS starts a rotating authorization server. It serves metadata
// with a max-age of metadataInterval, which is the effective metadata refresh
// interval for a client talking to it: the SDK honors the document's own cache
// headers, and its public client exposes no metadata-refresh-interval option,
// so the AS's cache header is the ordinary way to shorten the interval for a
// test. metadataInterval must be a whole number of seconds.
func newRotatingAS(t *testing.T, v1JWKS, v2JWKS []byte, metadataInterval time.Duration) *rotatingAS {
	t.Helper()

	as := &rotatingAS{}

	// The handlers need the server's own base URL. Read it from the listener
	// before Start rather than from srv.URL afterwards: the serving goroutine
	// exists from the moment the server is created, so a field assigned after
	// that point and read inside a handler is an unsynchronized access.
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	as.issuer = "http://" + srv.Listener.Addr().String()

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		as.metadataReads.Add(1)
		jwksURI := as.issuer + "/jwks-v1.json"
		if as.rotated.Load() {
			jwksURI = as.issuer + "/jwks-v2.json"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(metadataInterval.Seconds())))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   as.issuer,
			"jwks_uri": jwksURI,
		})
	})

	mux.HandleFunc("/jwks-v1.json", func(w http.ResponseWriter, _ *http.Request) {
		as.v1Reads.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(v1JWKS)
	})

	mux.HandleFunc("/jwks-v2.json", func(w http.ResponseWriter, _ *http.Request) {
		// The rotated key is published as part of the rotation, so before it
		// the document does not exist and nothing can reach the new key early.
		if !as.rotated.Load() {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		as.v2Reads.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(v2JWKS)
	})

	srv.Config.Handler = mux
	srv.Start()
	t.Cleanup(srv.Close)

	return as
}

// rotate moves jwks_uri to the second document and publishes the rotated key
// there.
//
// The first document is not taken down; it keeps serving the key it always
// served, now retired. The catalog allows either ("withdrawn or serves only
// retired keys") and this is the harder of the two to follow: a verifier still
// bound to the old URI keeps getting a well-formed key set with a key under
// the rotation kid, so nothing about the response tells it that it is looking
// in the wrong place.
func (as *rotatingAS) rotate() { as.rotated.Store(true) }

// metadataJWKSURI reads the jwks_uri the AS currently advertises, over plain
// HTTP and outside the SDK. The controls below use it to anchor themselves: a
// control that shows a verifier failing to follow a rotation proves nothing
// unless the AS is known to have rotated.
func (as *rotatingAS) metadataJWKSURI(t *testing.T) string {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, as.issuer+"/.well-known/oauth-authorization-server", nil)
	if err != nil {
		t.Fatalf("build AS metadata request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("read AS metadata: %v", err)
	}
	defer resp.Body.Close()
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode AS metadata: %v", err)
	}
	return doc.JWKSURI
}

// rotationToken signs an access token for the rotating AS with the given key
// and kid.
func rotationToken(t *testing.T, key *ecdsa.PrivateKey, kid, issuer, audience string) string {
	t.Helper()
	claims := testutil.StandardClaims(issuer, audience, "user-1", "client-1")
	token, err := testutil.SignToken(claims, key, jose.ES256, kid)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

// rotationKeyPair generates a signing key and the single-key JWKS document
// that publishes it under kid.
func rotationKeyPair(t *testing.T, kid string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwks, err := testutil.BuildJWKSWithKID(&key.PublicKey, kid)
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}
	return key, jwks
}

func TestRFC8414JWKSURIRotationMustReconfigureJWKSCache(t *testing.T) {
	Case(t, "rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache", Full(
		"Driven entirely through the public API — authplane.NewClient, then repeated "+
			"Resource.VerifyToken calls — with no force-refresh argument, no test-only hook and "+
			"no access to cache internals. The rotated signing key is published only at the new "+
			"jwks_uri and both key sets carry one kid, so a cache still bound to the withdrawn "+
			"URI fails on the signature rather than on a missing key, and only a real rebind can "+
			"make the token verify. All three side effects are asserted against request counts on "+
			"the serving test AS. Lateness bound: the JWKS fetch re-resolves jwks_uri through the "+
			"metadata cache on every fetch, so a rotation is followed within one metadata refresh "+
			"interval plus one JWKS cache TTL. That is inside the case's two-metadata-interval "+
			"bound whenever the effective JWKS TTL (the JWKS response's max-age, else "+
			"WithJWKSCacheTTL, default 5m) does not exceed the effective metadata interval (the "+
			"metadata response's max-age, else 1h). Both TTLs are read off the served document "+
			"and fall back to the configured value only when the response carries no cache "+
			"headers, so the AS decides whether the bound holds: one serving JWKS max-age=86400 "+
			"against metadata max-age=3600 sits outside it whatever the SDK is configured with. "+
			"This test reproduces the case that satisfies it, shortening the metadata interval "+
			"through the AS's own cache header and the JWKS TTL through WithJWKSCacheTTL."))

	const (
		metadataInterval = 2 * time.Second
		jwksTTL          = 500 * time.Millisecond
		resourceURI      = "https://api.example.com/mcp"
	)
	// The bound the catalog sets: the rotated key must verify within two
	// metadata refresh intervals of the rotation.
	const rotationBound = 2 * metadataInterval

	ctx := context.Background()

	retiredKey, v1JWKS := rotationKeyPair(t, rotationKID)
	rotatedKey, v2JWKS := rotationKeyPair(t, rotationKID)

	as := newRotatingAS(t, v1JWKS, v2JWKS, metadataInterval)

	client, err := authplane.NewClient(ctx, as.issuer,
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
		authplane.WithJWKSCacheTTL(jwksTTL),
	)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	res, err := client.Resource(resourceURI)
	if err != nil {
		t.Fatalf("new resource: %v", err)
	}

	// Ordinary traffic before the rotation: a token signed by the key the AS
	// publishes at the first jwks_uri verifies.
	claims, err := res.VerifyToken(ctx, rotationToken(t, retiredKey, rotationKID, as.issuer, resourceURI))
	if err != nil {
		t.Fatalf("token signed by the pre-rotation key must verify: %v", err)
	}
	if claims.KID() != rotationKID {
		t.Fatalf("kid = %q, want %q", claims.KID(), rotationKID)
	}
	if as.v1Reads.Load() == 0 {
		t.Fatal("the pre-rotation key set was never fetched")
	}
	if n := as.v2Reads.Load(); n != 0 {
		t.Fatalf("the rotated key set was fetched %d times before the rotation", n)
	}

	metadataReadsAtRotation := as.metadataReads.Load()
	as.rotate()
	rotatedAt := time.Now()

	rotatedToken := rotationToken(t, rotatedKey, rotationKID, as.issuer, resourceURI)

	// Immediately after the rotation nothing has re-read metadata, so the JWKS
	// cache is still bound to the withdrawn URI. Both documents publish
	// rotationKID, so the key lookup succeeds and the rejection is a signature
	// failure — this is the state the rebind has to get the verifier out of,
	// and asserting it here is what stops the acceptance below from being
	// something the verifier could have reached without following anything.
	_, err = res.VerifyToken(ctx, rotatedToken)
	if got := as.metadataReads.Load(); got != metadataReadsAtRotation {
		t.Fatalf("metadata was re-read %d times within %v of the rotation, so the pre-rebind state could not be observed; the run stalled",
			got-metadataReadsAtRotation, time.Since(rotatedAt))
	}
	if !errors.Is(err, verifier.ErrInvalidSignature) {
		t.Fatalf("before the rebind the rotated token must be rejected on the signature, got: %v", err)
	}

	// Ordinary verification traffic, repeated across the interval. Nothing in
	// this loop asks for a refresh: it calls one public method with one
	// argument, and the rebind has to come from the SDK's own cadence.
	var (
		accepted   bool
		acceptedIn time.Duration
		lastErr    error
	)
	deadline := rotatedAt.Add(rotationBound)
	for time.Now().Before(deadline) {
		_, err := res.VerifyToken(ctx, rotatedToken)
		if err == nil {
			accepted = true
			acceptedIn = time.Since(rotatedAt)
			break
		}
		// Any other rejection would mean the run measured something other than
		// the rotation — a missing key, an unreachable JWKS — so fail on it
		// rather than letting the loop spin to its deadline and report the
		// rotation as unfollowed.
		if !errors.Is(err, verifier.ErrInvalidSignature) {
			t.Fatalf("rotated token rejected for an unexpected reason: %v", err)
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	if !accepted {
		t.Fatalf("a token signed by the key published only at the rotated jwks_uri did not verify within %v (two metadata refresh intervals); last rejection: %v",
			rotationBound, lastErr)
	}
	t.Logf("rotation followed after %v (bound %v)", acceptedIn.Round(time.Millisecond), rotationBound)

	// side_effect: metadata re-fetched after the refresh interval elapses,
	// without an explicit refresh call. The test issued none.
	if got := as.metadataReads.Load(); got <= metadataReadsAtRotation {
		t.Errorf("metadata was not re-fetched after the rotation: %d reads, %d at the rotation", got, metadataReadsAtRotation)
	}
	// side_effect: JWKS fetched from the new jwks_uri.
	if as.v2Reads.Load() == 0 {
		t.Error("the rotated jwks_uri was never fetched")
	}

	// side_effect: no further fetch of the withdrawn document once the rebind
	// has happened. Keep verifying for several JWKS cache lifetimes — had the
	// verifier gone on resolving the old URI, its background refresh would
	// have returned there well inside this window.
	v1ReadsAtRebind := as.v1Reads.Load()
	settle := time.Now().Add(3 * jwksTTL)
	for time.Now().Before(settle) {
		if _, err := res.VerifyToken(ctx, rotatedToken); err != nil {
			t.Fatalf("verification regressed after the rebind: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := as.v1Reads.Load(); got != v1ReadsAtRebind {
		t.Errorf("the withdrawn jwks_uri was fetched %d more times after the rebind", got-v1ReadsAtRebind)
	}
}

// TestRFC8414RotationControlPinnedJWKSURIMustFailOnSignature is a negative
// control for the case above.
//
// It runs the identical rotation against a verifier that captures jwks_uri
// once and only ever refreshes keys from that URI — the implementation the
// catalog case exists to catch, described in the case's own notes as "a
// verifier that only refreshes keys from a URI captured at construction". The
// rotation must not be followed, and the rejection must be a signature failure
// rather than a missing key: that is the single-kid design doing its job, and
// without it this control would be indistinguishable from a lookup miss.
func TestRFC8414RotationControlPinnedJWKSURIMustFailOnSignature(t *testing.T) {
	const (
		metadataInterval = 1 * time.Second
		jwksTTL          = 250 * time.Millisecond
		resourceURI      = "https://api.example.com/mcp"
	)

	ctx := context.Background()

	retiredKey, v1JWKS := rotationKeyPair(t, rotationKID)
	rotatedKey, v2JWKS := rotationKeyPair(t, rotationKID)

	as := newRotatingAS(t, v1JWKS, v2JWKS, metadataInterval)

	pinnedURI := as.issuer + "/jwks-v1.json"
	jwksCache := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			resp, err := ssrf.SSRFSafeGet(ctx, pinnedURI, ssrf.DevModeFetchSettings(), nil, ssrf.MaxJWKSSize)
			if err != nil {
				return nil, nil, err
			}
			if resp.Status != http.StatusOK {
				return nil, nil, fmt.Errorf("JWKS fetch returned HTTP %d", resp.Status)
			}
			return resp.Body, nil, nil
		},
		DefaultTTL: jwksTTL,
	})
	defer jwksCache.Close()
	if err := jwksCache.Prime(ctx); err != nil {
		t.Fatalf("prime JWKS cache: %v", err)
	}

	res, err := resource.New(resourceURI, as.issuer, jwksCache)
	if err != nil {
		t.Fatalf("new resource: %v", err)
	}

	// Anchor: the control is wired correctly before the rotation.
	if _, err := res.VerifyToken(ctx, rotationToken(t, retiredKey, rotationKID, as.issuer, resourceURI)); err != nil {
		t.Fatalf("control setup is broken: the pre-rotation token must verify, got: %v", err)
	}

	as.rotate()
	rotatedAt := time.Now()

	// Anchor: the AS really did rotate. Read outside the SDK, so a verifier
	// that follows nothing cannot make this look true.
	if got, want := as.metadataJWKSURI(t), as.issuer+"/jwks-v2.json"; got != want {
		t.Fatalf("control setup is broken: AS advertises jwks_uri %q after the rotation, want %q", got, want)
	}

	rotatedToken := rotationToken(t, rotatedKey, rotationKID, as.issuer, resourceURI)

	deadline := rotatedAt.Add(2 * metadataInterval)
	for time.Now().Before(deadline) {
		_, err := res.VerifyToken(ctx, rotatedToken)
		if err == nil {
			t.Fatalf("a verifier pinned to the withdrawn jwks_uri accepted the rotated key after %v; the case would pass without following anything",
				time.Since(rotatedAt))
		}
		if !errors.Is(err, verifier.ErrInvalidSignature) {
			t.Fatalf("the pinned verifier must fail on the signature, not on key resolution: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}

	if n := as.v2Reads.Load(); n != 0 {
		t.Errorf("the pinned verifier fetched the rotated jwks_uri %d times", n)
	}
}

// TestRFC8414RotationControlSameKIDBlocksTheKIDMissShortcut measures the claim
// that publishing one kid on both key sets is what makes the rotation case
// sharp, rather than an incidental detail of the fixture.
//
// Both halves run the same configuration: metadata rotates promptly, but the
// JWKS cache TTL is an hour, so the interval-driven rebind cannot happen inside
// the test at all. The only remaining route to the rotated document is the
// unknown-kid escalation, which forces a JWKS re-fetch.
//
//   - With distinct kids the route is open in principle, but the forced-refresh
//     floor holds the kid-miss re-fetch for the whole window, so the rotated
//     token stays rejected on key resolution — and nothing in that half measures
//     the refresh interval either.
//   - With one kid the route is closed, the cached key is used, and the token
//     is rejected on the signature for as long as the cache stands.
func TestRFC8414RotationControlSameKIDBlocksTheKIDMissShortcut(t *testing.T) {
	const (
		metadataInterval = 1 * time.Second
		jwksTTL          = 1 * time.Hour
		resourceURI      = "https://api.example.com/mcp"
	)

	newRotatedClient := func(t *testing.T, rotatedKID string) (*rotatingAS, *resource.Resource, *ecdsa.PrivateKey) {
		t.Helper()
		ctx := context.Background()

		retiredKey, v1JWKS := rotationKeyPair(t, rotationKID)
		rotatedKey, v2JWKS := rotationKeyPair(t, rotatedKID)
		as := newRotatingAS(t, v1JWKS, v2JWKS, metadataInterval)

		client, err := authplane.NewClient(ctx, as.issuer,
			authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
			authplane.WithJWKSCacheTTL(jwksTTL),
		)
		if err != nil {
			t.Fatalf("new client: %v", err)
		}
		t.Cleanup(func() { _ = client.Close() })

		res, err := client.Resource(resourceURI)
		if err != nil {
			t.Fatalf("new resource: %v", err)
		}
		if _, err := res.VerifyToken(ctx, rotationToken(t, retiredKey, rotationKID, as.issuer, resourceURI)); err != nil {
			t.Fatalf("control setup is broken: the pre-rotation token must verify, got: %v", err)
		}
		as.rotate()
		return as, res, rotatedKey
	}

	t.Run("distinct kid is held by the forced-refresh floor", func(t *testing.T) {
		const rotatedKID = rotationKID + "-2"
		as, res, rotatedKey := newRotatedClient(t, rotatedKID)
		ctx := context.Background()

		rotatedToken := rotationToken(t, rotatedKey, rotatedKID, as.issuer, resourceURI)
		rotatedAt := time.Now()

		// Before the forced-refresh floor existed this half could go either way,
		// so it ended in a t.Skipf. It no longer can: the floor is
		// min(DefaultForcedRefreshFloor, jwksTTL) = 1m here, and this window is
		// 4s, so the kid-miss escalation is refused for the whole window and the
		// outcome is deterministic. Assert it rather than skip on it — a skip
		// that can never not fire is dead coverage propping up the half below.
		var lastErr error
		deadline := rotatedAt.Add(4 * metadataInterval)
		for time.Now().Before(deadline) {
			_, err := res.VerifyToken(ctx, rotatedToken)
			if err == nil {
				t.Fatalf("the rotated kid was accepted %v after rotation, inside a forced-refresh floor of %v: the floor is not holding the kid-miss re-fetch",
					time.Since(rotatedAt).Round(time.Millisecond), cache.DefaultForcedRefreshFloor)
			}
			// The cached key set holds nothing under the rotated kid, so
			// every rejection here has to come from key resolution. A
			// signature failure would mean the kid stopped selecting the key,
			// and the contrast this control draws would be measuring something
			// else entirely.
			if errors.Is(err, verifier.ErrInvalidSignature) {
				t.Fatalf("a distinct kid must be rejected on key resolution, not on the signature: %v", err)
			}
			lastErr = err
			time.Sleep(25 * time.Millisecond)
		}
		if lastErr == nil {
			t.Fatal("the window closed without a single verification attempt")
		}
		// The single-kid half below is the contrast: there the rebind carries the
		// rotation on the refresh interval, with no forced re-fetch involved.
		t.Logf("distinct kid still rejected after %v, as the forced-refresh floor requires; last rejection: %v",
			4*metadataInterval, lastErr)
	})

	t.Run("one kid closes the shortcut", func(t *testing.T) {
		as, res, rotatedKey := newRotatedClient(t, rotationKID)
		ctx := context.Background()

		rotatedToken := rotationToken(t, rotatedKey, rotationKID, as.issuer, resourceURI)
		rotatedAt := time.Now()

		deadline := rotatedAt.Add(2 * metadataInterval)
		for time.Now().Before(deadline) {
			_, err := res.VerifyToken(ctx, rotatedToken)
			if err == nil {
				t.Fatalf("the rotated token verified after %v although the JWKS cache TTL (%v) had not elapsed; the single-kid fixture is not closing the unknown-kid route",
					time.Since(rotatedAt), jwksTTL)
			}
			if !errors.Is(err, verifier.ErrInvalidSignature) {
				t.Fatalf("with one kid the rejection must be a signature failure, got: %v", err)
			}
			time.Sleep(25 * time.Millisecond)
		}
		if n := as.v2Reads.Load(); n != 0 {
			t.Errorf("the rotated jwks_uri was fetched %d times with no escalation to trigger it", n)
		}
	})
}
