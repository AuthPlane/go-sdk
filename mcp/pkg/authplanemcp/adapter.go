package authplanemcp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/mcp/internal/httputil"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// claimsKey is the context key used to store VerifiedClaims for downstream handlers.
type claimsKey struct{}

// tokenKey is the context key used to store the raw bearer token for downstream handlers.
type tokenKey struct{}

// claimsBoxKey is the context key for the per-request claimsBox used to pass
// VerifiedClaims from the verifyToken callback to the inner handler without
// a second VerifyToken call.
type claimsBoxKey struct{}

// claimsBox is a per-request mutable container that allows verifyToken to pass
// VerifiedClaims to the inner handler through the request context. This avoids
// a second VerifyToken call (and duplicate introspection round-trip).
type claimsBox struct {
	claims *verifier.VerifiedClaims
	token  string
}

// Options holds the configuration for creating an Adapter.
type Options struct {
	// Required
	Issuer   string
	Resource string
	Scopes   []string

	// DevMode relaxes SSRF protection to allow HTTP and localhost — required when
	// the issuer runs on a local development server. Remove before deploying to production.
	// The SDK also checks the AUTHPLANE_DEV_MODE=1 env var as a fallback.
	DevMode bool

	// ClientOptions are SDK-level options: WithClientCredentials, WithClientAuthentication,
	// WithJWKSCacheTTL, WithCircuitBreaker, WithDPoP, etc.
	//
	// When WithClientCredentials or WithClientAuthentication is present, RFC 7662
	// introspection is automatically wired as the default revocation checker.
	// To disable it, pass verifier.WithRevocationChecker(verifier.NullRevocationChecker)
	// in VerifierOptions.
	ClientOptions []authplane.Option

	// VerifierOptions are verifier-level options: WithAlgorithms, WithClockSkew,
	// WithRevocationChecker (overrides auto-wired introspection), etc.
	VerifierOptions []verifier.Option
}

// Adapter provides authentication middleware and resource metadata handlers
// for integrating with the MCP Go SDK and the authplane authentication system.
//
// Always call Close() when the adapter is no longer needed to stop background
// refresh goroutines and release HTTP connections.
type Adapter struct {
	client   *authplane.Client
	resource *resource.Resource
	prmURL   string // full URL for WWW-Authenticate ResourceMetadataURL
}

// NewAdapter creates and initializes an Adapter. It calls authplane.NewClient,
// which performs RFC 8414 AS metadata discovery and warms the JWKS cache.
//
// When ClientOptions includes WithClientCredentials or WithClientAuthentication,
// RFC 7662 introspection is automatically wired as the default revocation checker,
// and TokenExchange becomes operational.
//
// The provided ctx is used only for initial discovery; background refresh
// goroutines use their own context. Call Close() when the adapter is no longer needed.
func NewAdapter(ctx context.Context, options Options) (*Adapter, error) {
	// Prepend dev-mode fetch settings (when requested) so explicit ClientOptions
	// can override via their own WithFetchSettings.
	clientOpts := make([]authplane.Option, 0, 1+len(options.ClientOptions))
	if options.DevMode {
		clientOpts = append(clientOpts, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	}
	clientOpts = append(clientOpts, options.ClientOptions...)

	client, err := authplane.NewClient(ctx, options.Issuer, clientOpts...)
	if err != nil {
		return nil, err
	}

	resourceOpts := []resource.Option{resource.WithScopes(options.Scopes...)}
	if len(options.VerifierOptions) > 0 {
		// Only pass WithVerifierOptions when non-empty: WithVerifierOptions replaces
		// (not appends) the verifier option list, so passing an empty slice would
		// overwrite any options already auto-wired by client.Resource (e.g. the
		// RFC 7662 introspection revocation checker).
		resourceOpts = append(resourceOpts, resource.WithVerifierOptions(options.VerifierOptions...))
	}
	res, err := client.Resource(options.Resource, resourceOpts...)
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	resourceURL, err := url.Parse(options.Resource)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("authplane-mcp: invalid resource URL: %w", err)
	}
	prmURL := resourceURL.ResolveReference(&url.URL{Path: res.WellKnownPRMPath()}).String()

	return &Adapter{
		client:   client,
		resource: res,
		prmURL:   prmURL,
	}, nil
}

// NewAdapterFromClientAndResource creates an Adapter from an already-configured
// authplane.Client and resource.Resource. The caller retains ownership of both
// objects and is responsible for closing the client when done — adapter.Close()
// is a no-op for adapters created this way.
//
// Use this when you need to share a single client across multiple adapters, or
// when you need full control over client and resource construction.
func NewAdapterFromClientAndResource(client *authplane.Client, res *resource.Resource) (*Adapter, error) {
	resourceURL, err := url.Parse(res.URI())
	if err != nil {
		return nil, fmt.Errorf("authplane-mcp: invalid resource URL: %w", err)
	}
	prmURL := resourceURL.ResolveReference(&url.URL{Path: res.WellKnownPRMPath()}).String()

	return &Adapter{
		client:   client,
		resource: res,
		prmURL:   prmURL,
	}, nil
}

// AuthMiddleware returns an HTTP handler that enforces bearer token authentication.
//
// It uses auth.RequireBearerToken from the MCP go-sdk so that auth.TokenInfo is
// correctly placed in the context — the MCP streamable transport reads it for
// session hijacking protection (binding UserID to a session).
//
// The MCP go-sdk has a bug where it emits an unquoted URL in the WWW-Authenticate
// header (e.g. Bearer resource_metadata=http://...) which violates RFC 6750 §3
// and causes MCP clients to fail discovery. httputil.WWWAuthenticateQuoter
// intercepts the header and adds the required quotes before it reaches the client.
//
// On success the verified claims are also injected into the request context and are
// accessible via ClaimsFromContext — allowing individual tool handlers to perform
// fine-grained per-tool scope checks. A per-request claimsBox is used to pass
// claims from the verifyToken callback to the inner handler without a second
// VerifyToken call.
func (a *Adapter) AuthMiddleware(handler http.Handler) http.Handler {
	// inner reads the already-verified claims from the claimsBox that
	// verifyToken populated, and injects them into context for downstream
	// tool handlers. No second VerifyToken call is needed.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if box, ok := r.Context().Value(claimsBoxKey{}).(*claimsBox); ok && box.claims != nil {
			ctx := context.WithValue(r.Context(), claimsKey{}, box.claims)
			ctx = context.WithValue(ctx, tokenKey{}, box.token)
			r = r.WithContext(ctx)
		}
		handler.ServeHTTP(w, r)
	})

	// Scopes are NOT checked here — individual tool handlers enforce per-tool
	// scope via ClaimsFromContext + RequireScope. The initialize handshake and
	// other protocol messages must succeed with any valid token.
	mux := auth.RequireBearerToken(a.verifyToken, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: a.prmURL,
	})(inner)

	// Wrap with httputil.WWWAuthenticateQuoter to ensure the WWW-Authenticate header
	// emitted by the MCP go-sdk is RFC 6750 §3.1 compliant.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Inject an empty claimsBox into context for verifyToken to populate.
		ctx := context.WithValue(r.Context(), claimsBoxKey{}, &claimsBox{})
		mux.ServeHTTP(&httputil.WWWAuthenticateQuoter{ResponseWriter: w}, r.WithContext(ctx))
	})
}

// ProtectedResourceMetadataHandler returns an HTTP handler that serves the
// Protected Resource Metadata (PRM) document as JSON per RFC 9728. Only GET
// is allowed; other methods return 405.
func (a *Adapter) ProtectedResourceMetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		_, _ = w.Write(a.resource.PRMJSON())
	})
}

// WellKnownPRMPath returns the RFC 9728 well-known path for this resource,
// e.g. "/.well-known/oauth-protected-resource/mcp".
//
// Use this to register the PRM handler:
//
//	http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
func (a *Adapter) WellKnownPRMPath() string {
	return a.resource.WellKnownPRMPath()
}

// Client returns the underlying authplane.Client, providing access to all SDK
// operations: TokenExchange, Revoke, Introspect, ClientCredentials, DPoPSigner, etc.
//
// Do not call Close() on the returned client directly — call adapter.Close() instead,
// as the adapter owns the client lifecycle.
func (a *Adapter) Client() *authplane.Client {
	return a.client
}

// Resource returns the underlying resource.Resource, providing access to token
// verification with custom options (e.g. DPoP), PRM generation, and the well-known path.
func (a *Adapter) Resource() *resource.Resource {
	return a.resource
}

// TokenFromContext returns the raw bearer token injected by AuthMiddleware into
// the request context. Returns an empty string if called outside an authenticated request.
//
// Use this inside MCP tool handlers when the raw token is needed — for example,
// to revoke or exchange the caller's token via adapter.Client():
//
//	token := authplanemcp.TokenFromContext(ctx)
//	err := adapter.Client().Revoke(ctx, token)
func TokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(tokenKey{}).(string)
	return token
}

// Close stops all background goroutines and releases resources held by the
// underlying client. It is safe to call Close multiple times.
//
// When using NewAdapterFromClientAndResource and sharing a client across multiple
// adapters, call client.Close() directly instead of adapter.Close().
func (a *Adapter) Close() error {
	return a.client.Close()
}

// defaultConsentMessage is used when ConsentRequiredError.Description is empty.
const defaultConsentMessage = "Consent is required to proceed"

// ConsentElicitationError checks whether err wraps an *authplane.ConsentRequiredError
// with a non-empty ConsentURL. If so, it returns an mcp.URLElicitationRequiredError
// that directs the MCP client to open the consent URL for out-of-band user interaction.
//
// If err is nil, not a ConsentRequiredError, or has an empty ConsentURL, the original
// error is returned unchanged.
func ConsentElicitationError(err error) error {
	if err == nil {
		return nil
	}
	var consentErr *authplane.ConsentRequiredError
	if !errors.As(err, &consentErr) || consentErr.ConsentURL == "" {
		return err
	}
	msg := consentErr.Description
	if msg == "" {
		msg = defaultConsentMessage
	}
	return mcp.URLElicitationRequiredError([]*mcp.ElicitParams{{
		Mode:          "url",
		URL:           consentErr.ConsentURL,
		Message:       msg,
		ElicitationID: newUUID(),
	}})
}

// TokenExchange performs an RFC 8693 token exchange via the underlying client and
// automatically maps ConsentRequiredError to mcp.URLElicitationRequiredError when
// a consent URL is available. This triggers the MCP client's URL elicitation flow
// so the user can complete consent out-of-band, after which the client retries the
// original operation.
//
// For custom consent handling, use Client().TokenExchange() directly and pass the
// error through ConsentElicitationError.
func (a *Adapter) TokenExchange(ctx context.Context, input authplane.TokenExchangeInput) (*authplane.TokenResponse, error) {
	resp, err := a.client.TokenExchange(ctx, input)
	if err != nil {
		return nil, ConsentElicitationError(err)
	}
	return resp, nil
}

// newUUID generates a random v4 UUID string without external dependencies.
func newUUID() string {
	var u [16]byte
	_, _ = rand.Read(u[:])      // crypto/rand.Read never returns an error on supported platforms
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// verifyToken is the token verification callback used by auth.RequireBearerToken.
// Errors are wrapped with auth.ErrInvalidToken so the go-sdk returns 401 (not 500)
// and sets the WWW-Authenticate header on the response.
func (a *Adapter) verifyToken(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	claims, err := a.resource.VerifyToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", auth.ErrInvalidToken, err)
	}
	// Pass verified claims to the inner handler via the per-request claimsBox,
	// avoiding a second VerifyToken call (and duplicate introspection round-trip).
	if box, ok := ctx.Value(claimsBoxKey{}).(*claimsBox); ok {
		box.claims = claims
		box.token = token
	}
	return &auth.TokenInfo{
		Scopes:     claims.Scopes(),
		Expiration: time.Unix(claims.ExpiresAt(), 0),
		UserID:     claims.Sub(),
	}, nil
}

// ClaimsFromContext returns the VerifiedClaims injected by AuthMiddleware into
// the request context. Returns nil if called outside an authenticated request.
//
// Use this inside MCP tool handlers to enforce per-tool scope:
//
//	claims := authplanemcp.ClaimsFromContext(ctx)
//	if err := claims.RequireScope("tools/add"); err != nil {
//	    return nil, nil, err
//	}
func ClaimsFromContext(ctx context.Context) *verifier.VerifiedClaims {
	claims, _ := ctx.Value(claimsKey{}).(*verifier.VerifiedClaims)
	return claims
}
