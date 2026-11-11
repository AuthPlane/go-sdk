// Package authplanemcp is the auth adapter for the official MCP Go SDK: bearer token middleware,
// RFC 9728 metadata, per-tool scopes and claims for tool handlers.
package authplanemcp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/mcp/internal/httputil"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// claimsKey is the context key for the claimsHolder of the current request.
type claimsKey struct{}

// claimsBoxKey is the context key for the per-request claimsBox.
type claimsBoxKey struct{}

// TokenInfo.Extra keys carrying the verified claims and raw token with each request.
const (
	extraClaimsKey = "authplane.claims"
	extraTokenKey  = "authplane.token"
)

// claimsBox carries the outcome of verification and the caller's response writer
// through the MCP SDK's auth middleware.
type claimsBox struct {
	claims   *verifier.VerifiedClaims
	token    string
	err      error
	verified bool
	writer   http.ResponseWriter
}

// claimsHolder is what the context carries. An MCP session keeps the context of the
// request that created it, so a value stored there outlives that request. The holder is
// closed when its request ends, so a later call in the session reads nothing rather
// than a token that may since have been narrowed or replaced.
type claimsHolder struct {
	claims *verifier.VerifiedClaims
	token  string
	closed atomic.Bool
}

// Options holds the configuration for creating an Adapter.
type Options struct {
	// Required
	Issuer   string
	Resource string

	// Scopes are the scopes this resource advertises. Optional.
	Scopes []string

	// ResourceMetadataURL overrides the URL advertised in the RFC 9728 §5.1
	// resource_metadata parameter of the WWW-Authenticate challenge. Leave it
	// empty to advertise the document this adapter serves itself; set it to the
	// authorization server's copy ("<issuer>/.well-known/oauth-protected-resource/{ref}")
	// when the resource server cannot host well-known paths. Rejected at
	// construction if it is not an absolute http(s) URL.
	ResourceMetadataURL string

	// Logger receives this adapter's logs. Nil means slog's default. Pass authplane.WithLogger
	// in ClientOptions for the client's own logs.
	Logger *slog.Logger

	// DevMode relaxes SSRF protection to allow HTTP and localhost — required when
	// the issuer runs on a local development server. Remove before deploying to production.
	DevMode bool

	// ClientOptions are SDK-level options: WithClientCredentials, WithClientAuthentication,
	// WithJWKSCacheTTL, WithCircuitBreaker, WithDPoP, etc.
	ClientOptions []authplane.Option

	// VerifierOptions are verifier-level options: WithAlgorithms, WithClockSkew,
	// WithRevocationChecker (overrides auto-wired introspection), etc.
	VerifierOptions []verifier.Option
}

// Adapter provides authentication middleware and resource metadata handlers
// for integrating with the MCP Go SDK and the authplane authentication system.
//
// Always call Close() when the adapter is no longer needed to stop background
// refresh goroutines.
type Adapter struct {
	logger   *slog.Logger // nil means slog's default at the time
	client   *authplane.Client
	resource *resource.Resource
	// resourceMetadataURL is the full URL handed to the MCP go-sdk's
	// RequireBearerTokenOptions.ResourceMetadataURL — the derived PRM URL, or
	// the override from resource.WithResourceMetadataURL when the document is
	// hosted elsewhere (typically by the authorization server).
	resourceMetadataURL string
	scopeHint           string // space-joined resource scopes advertised in the 401 scope param (RFC 6750 §3); empty when none configured
	ownsClient          bool   // true when this Adapter constructed the client and must close it
}

// NewAdapter creates and initializes an Adapter. It calls authplane.NewClient,
// which performs RFC 8414 AS metadata discovery and warms the JWKS cache.
func NewAdapter(ctx context.Context, options Options) (*Adapter, error) {
	client, res, err := authplane.NewClientAndResource(ctx, authplane.Setup{
		Issuer:              options.Issuer,
		Resource:            options.Resource,
		Scopes:              options.Scopes,
		ResourceMetadataURL: options.ResourceMetadataURL,
		DevMode:             options.DevMode,
		ClientOptions:       options.ClientOptions,
		VerifierOptions:     options.VerifierOptions,
	})
	if err != nil {
		return nil, err
	}

	return &Adapter{
		logger:              options.Logger,
		client:              client,
		resource:            res,
		resourceMetadataURL: res.ResourceMetadataURL(),
		scopeHint:           strings.Join(res.PRMConfig().ScopesSupported, " "),
		ownsClient:          true,
	}, nil
}

// NewAdapterFromClientAndResource creates an Adapter from an already-configured
// authplane.Client and resource.Resource. The caller retains ownership of both
// objects and is responsible for closing the client when done — adapter.Close()
// is a no-op for adapters created this way.
func NewAdapterFromClientAndResource(client *authplane.Client, res *resource.Resource) (*Adapter, error) {
	if client == nil {
		return nil, errors.New("authplane-mcp: client must not be nil")
	}
	if res == nil {
		return nil, errors.New("authplane-mcp: res must not be nil")
	}
	return &Adapter{
		client:              client,
		resource:            res,
		resourceMetadataURL: res.ResourceMetadataURL(),
		scopeHint:           strings.Join(res.PRMConfig().ScopesSupported, " "),
		ownsClient:          false,
	}, nil
}

// AuthMiddleware returns an HTTP handler that enforces bearer token authentication.
func (a *Adapter) AuthMiddleware(handler http.Handler) http.Handler {
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		box, _ := r.Context().Value(claimsBoxKey{}).(*claimsBox)
		if box == nil {
			return
		}
		holder := &claimsHolder{claims: box.claims, token: box.token}
		defer holder.closed.Store(true)
		handler.ServeHTTP(box.writer, r.WithContext(context.WithValue(r.Context(), claimsKey{}, holder)))
	})

	// Scopes are NOT checked here — use RequireToolScopes or per-tool checks. Protocol
	// messages must succeed with any valid token. Core has already applied its own
	// expiry check and clock skew, so the SDK's repeat of it must never be stricter.
	mux := auth.RequireBearerToken(a.verifyToken, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: a.resourceMetadataURL,
		ClockSkew:           verifier.MaxClockSkew,
	})(inner)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		box := &claimsBox{writer: w}
		if token := bearerToken(r); token != "" {
			box.token = token
			box.verified = true
			box.claims, box.err = a.resource.VerifyToken(r.Context(), token)
			if box.err != nil {
				status := resource.HTTPStatus(box.err)
				if status >= http.StatusInternalServerError {
					// A caller who left is not an outage.
					if !errors.Is(box.err, context.Canceled) && !errors.Is(box.err, context.DeadlineExceeded) {
						a.log().ErrorContext(r.Context(), "authplane: cannot verify tokens", "error", box.err, "status", status)
					}
					a.writeError(w, box.err)
					return
				}
				a.log().DebugContext(r.Context(), "authplane: rejecting request", "error", box.err, "status", status)
			}
		}
		ctx := context.WithValue(r.Context(), claimsBoxKey{}, box)
		hinted := &httputil.WWWAuthenticateScopeHint{ResponseWriter: w, Scope: a.scopeHint}
		mux.ServeHTTP(&httputil.WWWAuthenticateQuoter{ResponseWriter: hinted}, r.WithContext(ctx))
	})
}

// bearerToken reads the token the way the MCP go-sdk does.
func bearerToken(r *http.Request) string {
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "bearer") {
		return ""
	}
	return fields[1]
}

func (a *Adapter) writeError(w http.ResponseWriter, err error) {
	status, headers, body := a.resource.AuthErrorResponse(err, resource.WithChallengeMetadata(a.resourceMetadataURL))
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// ReceivingMiddleware returns MCP middleware that gives each call the claims and token of
// its own HTTP request, for ClaimsFromContext and TokenFromContext. Add it to the server:
//
//	server.AddReceivingMiddleware(adapter.ReceivingMiddleware())
func (a *Adapter) ReceivingMiddleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			holder := &claimsHolder{claims: ClaimsFromRequest(req)}
			if holder.claims != nil {
				holder.token, _ = req.GetExtra().TokenInfo.Extra[extraTokenKey].(string)
			}
			return next(context.WithValue(ctx, claimsKey{}, holder), method, req)
		}
	}
}

// ClaimsFromRequest returns the claims verified for this request, or nil.
func ClaimsFromRequest(req mcp.Request) *verifier.VerifiedClaims {
	extra := req.GetExtra()
	if extra == nil || extra.TokenInfo == nil {
		return nil
	}
	claims, _ := extra.TokenInfo.Extra[extraClaimsKey].(*verifier.VerifiedClaims)
	return claims
}

// ToolScopeOption adjusts RequireToolScopes.
type ToolScopeOption func(*toolScopeConfig)

type toolScopeConfig struct {
	refuseUnlisted bool
}

// RefuseUnlistedTools answers 403 for a tool not in the map, so a newly added tool has no access
// until someone decides its scopes. List a tool with no scopes to allow it for any token.
func RefuseUnlistedTools() ToolScopeOption {
	return func(c *toolScopeConfig) { c.refuseUnlisted = true }
}

// RequireToolScopes returns HTTP middleware, for use inside AuthMiddleware, that answers a
// tools/call missing a required scope with 403 and an insufficient_scope challenge before
// the tool runs, so the client can step up. See resource.ToolScopeGuard.
func (a *Adapter) RequireToolScopes(toolScopes map[string][]string, opts ...ToolScopeOption) func(http.Handler) http.Handler {
	var cfg toolScopeConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return resource.ToolScopeGuard(resource.ToolScopeGuardConfig{
		Claims:              func(r *http.Request) *verifier.VerifiedClaims { return ClaimsFromContext(r.Context()) },
		ResourceMetadataURL: a.resourceMetadataURL,
		ToolScopes:          toolScopes,
		RefuseUnlisted:      cfg.refuseUnlisted,
	})
}

// PRMHandler serves the Protected Resource Metadata document; see resource.Resource.PRMHandler.
func (a *Adapter) PRMHandler() http.Handler {
	return a.resource.PRMHandler()
}

func (a *Adapter) log() *slog.Logger {
	if a.logger != nil {
		return a.logger
	}
	return slog.Default()
}

// Middleware is AuthMiddleware in the shape net/http middleware chains use.
func (a *Adapter) Middleware() func(http.Handler) http.Handler {
	return a.AuthMiddleware
}

// WellKnownPRMPath returns the RFC 9728 well-known path for this resource,
// e.g. "/.well-known/oauth-protected-resource/mcp".
//
// Use this to register the PRM handler:
//
//	http.Handle(adapter.WellKnownPRMPath(), adapter.PRMHandler())
func (a *Adapter) WellKnownPRMPath() string {
	return a.resource.WellKnownPRMPath()
}

// Client returns the underlying authplane.Client, providing access to all SDK
// operations: TokenExchange, Revoke, Introspect, ClientCredentials, DPoPSigner, etc.
func (a *Adapter) Client() *authplane.Client {
	return a.client
}

// Resource returns the underlying resource.Resource, providing access to token
// verification with custom options (e.g. DPoP), PRM generation, and the well-known path.
func (a *Adapter) Resource() *resource.Resource {
	return a.resource
}

// TokenFromContext returns the raw bearer token of the current request, on the same terms
// as ClaimsFromContext, or an empty string.
//
// Use it inside MCP tool handlers when the raw token is needed — for example, to revoke or
// exchange the caller's token via adapter.Client(). Never forward it to an upstream API:
// the MCP authorization spec forbids token passthrough, so exchange it instead.
//
//	token := authplanemcp.TokenFromContext(ctx)
//	err := adapter.Client().Revoke(ctx, token)
func TokenFromContext(ctx context.Context) string {
	holder := currentHolder(ctx)
	if holder == nil {
		return ""
	}
	return holder.token
}

func currentHolder(ctx context.Context) *claimsHolder {
	holder, _ := ctx.Value(claimsKey{}).(*claimsHolder)
	if holder == nil || holder.closed.Load() {
		return nil
	}
	return holder
}

// Close stops all background goroutines and releases resources held by the
// underlying client. It is safe to call Close multiple times.
func (a *Adapter) Close() error {
	if !a.ownsClient {
		return nil
	}
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
		ElicitationID: authplane.NewElicitationID(),
	}})
}

// TokenExchange performs an RFC 8693 token exchange via the underlying client and
// automatically maps ConsentRequiredError to mcp.URLElicitationRequiredError when
// a consent URL is available. This triggers the MCP client's URL elicitation flow
// so the user can complete consent out-of-band, after which the client retries the
// original operation.
func (a *Adapter) TokenExchange(ctx context.Context, input authplane.TokenExchangeInput) (*authplane.TokenResponse, error) {
	resp, err := a.client.TokenExchange(ctx, input)
	if err != nil {
		return nil, ConsentElicitationError(err)
	}
	return resp, nil
}

// verifyToken is the token verification callback used by auth.RequireBearerToken. The
// outcome comes from AuthMiddleware, which has already run the verification. Errors are
// bare auth.ErrInvalidToken so the go-sdk answers 401 and the body holds no verifier text.
func (a *Adapter) verifyToken(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	box, _ := ctx.Value(claimsBoxKey{}).(*claimsBox)
	if box == nil || !box.verified {
		return nil, auth.ErrInvalidToken
	}
	if box.err != nil || box.claims == nil {
		return nil, auth.ErrInvalidToken
	}
	return &auth.TokenInfo{
		Scopes:     box.claims.Scopes(),
		Expiration: time.Unix(box.claims.ExpiresAt(), 0),
		UserID:     box.claims.Sub(),
		Extra:      map[string]any{extraClaimsKey: box.claims, extraTokenKey: token},
	}, nil
}

// ClaimsFromContext returns the verified claims of the current request, or nil outside an
// authenticated request, including a later call in a legacy session on a server without
// ReceivingMiddleware. Nil claims have no scopes, so the check below refuses.
//
// Use this inside MCP tool handlers to enforce per-tool scope:
//
//	claims := authplanemcp.ClaimsFromContext(ctx)
//	if err := claims.RequireScope("tools/add"); err != nil {
//	    return nil, nil, err
//	}
func ClaimsFromContext(ctx context.Context) *verifier.VerifiedClaims {
	holder := currentHolder(ctx)
	if holder == nil {
		return nil
	}
	return holder.claims
}
