// Package authplanemark3labs is the Authplane adapter for the mark3labs/mcp-go
// server library.
//
// It is a thin layer over the generic Authplane net/http adapter
// (github.com/authplane/go-sdk/http/pkg/authplanehttp) that adds the two
// things genuinely specific to mark3labs/mcp-go:
//
//   - HTTPContextFunc — bridges verified claims from the HTTP request context
//     into the per-tool-call MCP context that mark3labs/mcp-go exposes via
//     server.WithHTTPContextFunc.
//   - URLElicitationError / ConsentElicitationError — maps RFC 8693
//     token-exchange consent errors to the MCP URL elicitation shape
//     (JSON-RPC -32042).
//
// Bearer/DPoP parsing, the RFC 6750 WWW-Authenticate challenge (including the
// RFC 9728 resource_metadata advertisement), context keys, and scope-enforcing
// middleware all come from the wrapped *authplanehttp.Adapter. PRM is served
// via mark3labs/mcp-go's server.NewProtectedResourceMetadataHandler so the
// HTTP framing (CORS, Cache-Control: no-store, allowed methods) matches the
// MCP authorization spec, while core remains the source of the field values.
package authplanemark3labs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
	authplanehttp "github.com/authplane/go-sdk/http/pkg/authplanehttp"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

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

	// AllowUnboundSessions lets a session be used by any authenticated caller, as it
	// was before sessions were bound to users. Prefer SessionManager.
	AllowUnboundSessions bool

	// SessionKey signs session IDs, and must be shared by replicas. At least 32 bytes.
	// Empty uses a random per-process key, which suits one instance.
	SessionKey []byte `json:"-"`
}

// SessionOptions configures session binding for NewAdapterFromClientAndResource. The fields
// mean what Options.AllowUnboundSessions and Options.SessionKey mean.
type SessionOptions struct {
	AllowUnbound bool
	Key          []byte `json:"-"`
}

// String keeps the session key out of logs and %v.
func (o Options) String() string {
	return fmt.Sprintf("{Issuer:%s Resource:%s DevMode:%v AllowUnboundSessions:%v}", o.Issuer, o.Resource, o.DevMode, o.AllowUnboundSessions)
}

// GoString keeps the session key out of %#v.
func (o Options) GoString() string { return o.String() }

// LogValue keeps the session key out of structured logs.
func (o Options) LogValue() slog.Value { return slog.StringValue(o.String()) }

// String keeps the session key out of logs and %v.
func (o SessionOptions) String() string { return fmt.Sprintf("{AllowUnbound:%v}", o.AllowUnbound) }

// GoString keeps the session key out of %#v.
func (o SessionOptions) GoString() string { return o.String() }

// LogValue keeps the session key out of structured logs.
func (o SessionOptions) LogValue() slog.Value { return slog.StringValue(o.String()) }

// Adapter integrates the Authplane core SDK with mark3labs/mcp-go.
type Adapter struct {
	http *authplanehttp.Adapter

	client     *authplane.Client
	prmHandler http.Handler // mark3labs PRM handler, built once at construction
	sessions   *sessionBinder
	ownsClient bool // true when this Adapter constructed the client and must close it
}

// ClaimsFromContext returns the VerifiedClaims injected by Middleware (and
// forwarded by HTTPContextFunc) into the per-tool-call context. Returns nil
// when called outside an authenticated request.
func ClaimsFromContext(ctx context.Context) *verifier.VerifiedClaims {
	return authplanehttp.ClaimsFromContext(ctx)
}

// TokenFromContext returns the raw bearer token injected by Middleware (and
// forwarded by HTTPContextFunc). Returns "" outside an authenticated request.
// A thin wrapper around authplanehttp.TokenFromContext.
func TokenFromContext(ctx context.Context) string {
	return authplanehttp.TokenFromContext(ctx)
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

	sessions, err := newSessionBinder(options.SessionKey, options.AllowUnboundSessions)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	sessions.logger = options.Logger
	prm := withPRMAllow(server.NewProtectedResourceMetadataHandler(prmConfigFromResource(res)))
	httpAdapter, err := authplanehttp.New(res, authplanehttp.WithPRMHandler(prm), authplanehttp.WithLogger(options.Logger))
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return &Adapter{
		http:       httpAdapter,
		client:     client,
		prmHandler: prm,
		sessions:   sessions,
		ownsClient: true,
	}, nil
}

// NewAdapterFromClientAndResource creates an Adapter from an already-configured
// authplane.Client and resource.Resource. The caller retains ownership of the
// client — adapter.Close() is a no-op for adapters created this way, so a
// client shared across multiple adapters keeps running even after one of them
// is closed.
func NewAdapterFromClientAndResource(client *authplane.Client, res *resource.Resource, session SessionOptions) (*Adapter, error) {
	if client == nil {
		return nil, errors.New("authplanemark3labs: client must not be nil")
	}
	if res == nil {
		return nil, errors.New("authplanemark3labs: res must not be nil")
	}
	sessions, err := newSessionBinder(session.Key, session.AllowUnbound)
	if err != nil {
		return nil, err
	}
	prm := withPRMAllow(server.NewProtectedResourceMetadataHandler(prmConfigFromResource(res)))
	httpAdapter, err := authplanehttp.New(res, authplanehttp.WithPRMHandler(prm))
	if err != nil {
		return nil, err
	}
	return &Adapter{
		http:       httpAdapter,
		client:     client,
		prmHandler: prm,
		sessions:   sessions,
		ownsClient: false,
	}, nil
}

// AuthMiddleware returns an HTTP handler that enforces Bearer (and DPoP) token
// authentication in front of a mark3labs/mcp-go *server.StreamableHTTPServer. It also
// binds legacy sessions to the user, which needs SessionManager on the server, or
// Options.AllowUnboundSessions. server.SSEServer is not supported behind it.
//
// It is a thin wrapper over the wrapped *authplanehttp.Adapter's Middleware,
// preserving the mark3labs-style call shape used throughout the docs and demo:
//
//	http.Handle("/mcp", adapter.AuthMiddleware(streamable))
//
// On success the verified claims and raw token are stored in the *request*
// context (via authplanehttp's context keys). To forward them into the
// per-tool-call MCP context that mark3labs/mcp-go derives via
// server.WithHTTPContextFunc, wire HTTPContextFunc() when constructing the
// streamable server. Scope enforcement is per-tool — individual tool handlers
// call ClaimsFromContext(ctx).RequireScope(...).
func (a *Adapter) AuthMiddleware(handler http.Handler) http.Handler {
	return a.Middleware()(handler)
}

// Middleware is the wrapped http adapter's middleware plus the session binding, so a
// server using this name directly is protected the same way as with AuthMiddleware.
func (a *Adapter) Middleware() func(http.Handler) http.Handler {
	inner := a.http.Middleware()
	return func(next http.Handler) http.Handler {
		return inner(a.sessions.guard(next))
	}
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
		ResourceMetadataURL: a.Resource().ResourceMetadataURL(),
		ToolScopes:          toolScopes,
		RefuseUnlisted:      cfg.refuseUnlisted,
	})
}

// SessionManager returns the resolver that mints session IDs bound to the caller's client and sub.
// Pass it when constructing the streamable server:
//
//	server.NewStreamableHTTPServer(mcpServer,
//	    server.WithSessionIdManagerResolver(adapter.SessionManager()),
//	)
func (a *Adapter) SessionManager() server.SessionIdManagerResolver {
	return a.sessions
}

// HTTPContextOption configures HTTPContextFunc. See WithForwardedContextKeys
// and WithContextForwarding for the available options.
type HTTPContextOption func(*httpContextConfig)

type httpContextConfig struct {
	keys     []any
	mergeFns []func(parent, mcp context.Context) context.Context
}

// WithForwardedContextKeys forwards the listed keys from the upstream HTTP
// request context onto the per-tool-call MCP context, in addition to the
// verified claims and bearer token. Use this for upstream middleware that
// exposes its context key publicly (request IDs, feature flags, tenant
// resolvers).
func WithForwardedContextKeys(keys ...any) HTTPContextOption {
	return func(c *httpContextConfig) {
		c.keys = append(c.keys, keys...)
	}
}

// WithContextForwarding registers a merge function invoked on every
// tool-call context. The function receives the upstream request context
// (parent) and the new MCP context already populated with claims, bearer
// token, and any WithForwardedContextKeys values (mcp), and must return a
// context derived from mcp.
func WithContextForwarding(fn func(parent, mcp context.Context) context.Context) HTTPContextOption {
	return func(c *httpContextConfig) {
		if fn != nil {
			c.mergeFns = append(c.mergeFns, fn)
		}
	}
}

// HTTPContextFunc returns a server.HTTPContextFunc that forwards the verified
// claims and raw bearer token from the HTTP request context (where the
// wrapped http adapter's Middleware stored them) into the per-tool-call MCP
// context.
//
// Pass it to mark3labs/mcp-go when constructing the streamable HTTP server:
//
//	httpServer := server.NewStreamableHTTPServer(mcpServer,
//	    server.WithHTTPContextFunc(adapter.HTTPContextFunc()),
//	)
//	http.Handle("/mcp", adapter.AuthMiddleware(httpServer))
//
// Without this option, tool handlers receive a fresh context that does not see
// the values placed by AuthMiddleware.
//
// By default only the authentication pair (claims + token) is forwarded;
// values set on the upstream r.Context() by other middleware (tracing spans,
// request IDs, etc.) are NOT propagated. Pass WithForwardedContextKeys for
// the simple key-copy case, or WithContextForwarding for libraries whose
// context key is unexported.
func (a *Adapter) HTTPContextFunc(opts ...HTTPContextOption) server.HTTPContextFunc {
	var cfg httpContextConfig
	for _, o := range opts {
		o(&cfg)
	}
	return func(ctx context.Context, r *http.Request) context.Context {
		parent := r.Context()
		if claims := authplanehttp.ClaimsFromContext(parent); claims != nil {
			ctx = authplanehttp.ContextWithClaims(ctx, claims)
		}
		if token := authplanehttp.TokenFromContext(parent); token != "" {
			ctx = authplanehttp.ContextWithToken(ctx, token)
		}
		for _, k := range cfg.keys {
			if v := parent.Value(k); v != nil {
				ctx = context.WithValue(ctx, k, v)
			}
		}
		for _, fn := range cfg.mergeFns {
			ctx = fn(parent, ctx)
		}
		return ctx
	}
}

// PRMHandler serves the Protected Resource Metadata document with mark3labs/mcp-go's framing:
// permissive CORS and Cache-Control: no-store.
func (a *Adapter) PRMHandler() http.Handler {
	return a.prmHandler
}

// Resource returns the wrapped resource.Resource.
func (a *Adapter) Resource() *resource.Resource {
	return a.http.Resource()
}

// WellKnownPRMPath returns the RFC 9728 well-known path for this resource.
func (a *Adapter) WellKnownPRMPath() string {
	return a.http.WellKnownPRMPath()
}

// RequireScopes returns middleware that refuses a request without the given scopes.
func (a *Adapter) RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	return a.http.RequireScopes(scopes...)
}

// withPRMAllow names the allowed methods on the OPTIONS answer.
func withPRMAllow(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		}
		next.ServeHTTP(w, r)
	})
}

// prmConfigFromResource maps the typed PRM config from core into mark3labs/mcp-go's
// ProtectedResourceMetadataConfig so the JSON document can be served by
// server.NewProtectedResourceMetadataHandler.
func prmConfigFromResource(res *resource.Resource) server.ProtectedResourceMetadataConfig {
	src := res.PRMConfig()
	return server.ProtectedResourceMetadataConfig{
		Resource:                      src.Resource,
		AuthorizationServers:          src.AuthorizationServers,
		BearerMethodsSupported:        src.BearerMethodsSupported,
		ScopesSupported:               src.ScopesSupported,
		DPoPSigningAlgValuesSupported: src.DPoPSigningAlgValuesSupported,
		DPoPBoundAccessTokensRequired: src.DPoPBoundAccessTokensRequired,
	}
}

// Client returns the underlying authplane.Client, providing access to all SDK
// operations: TokenExchange, Revoke, Introspect, ClientCredentials, DPoPSigner, etc.
func (a *Adapter) Client() *authplane.Client {
	return a.client
}

// Close stops all background goroutines and releases resources held by the
// underlying client. It is safe to call multiple times.
func (a *Adapter) Close() error {
	if !a.ownsClient {
		return nil
	}
	return a.client.Close()
}

// defaultConsentMessage is used when ConsentRequiredError.Description is empty.
const defaultConsentMessage = "Consent is required to proceed"

// URLElicitationError carries the data for an MCP URL elicitation
// (JSON-RPC error code -32042). It is what ConsentElicitationError returns
// when it detects a consent-required error with a non-empty consent URL.
type URLElicitationError struct {
	Params mcp.ElicitationParams
	Cause  error
}

// Code returns the MCP URL elicitation error code (-32042).
func (e *URLElicitationError) Code() int { return mcp.URL_ELICITATION_REQUIRED }

// Error implements the error interface, returning the elicitation message.
func (e *URLElicitationError) Error() string {
	if e.Params.Message != "" {
		return e.Params.Message
	}
	return defaultConsentMessage
}

// Unwrap returns the underlying cause, so errors.Is / errors.As can reach
// the original ConsentRequiredError.
func (e *URLElicitationError) Unwrap() error { return e.Cause }

// MarshalData returns the JSON-encoded ElicitationParams payload suitable for
// the data field of a JSON-RPC -32042 error.
func (e *URLElicitationError) MarshalData() ([]byte, error) {
	return json.Marshal(e.Params)
}

// ConsentElicitationError checks whether err wraps an *authplane.ConsentRequiredError
// with a non-empty ConsentURL. If so, it returns a *URLElicitationError carrying
// the URL, the AS-provided description (falling back to a default), and a freshly
// minted elicitation ID. Otherwise the original error is returned unchanged.
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
	return &URLElicitationError{
		Params: mcp.ElicitationParams{
			Mode:          "url",
			URL:           consentErr.ConsentURL,
			Message:       msg,
			ElicitationID: authplane.NewElicitationID(),
		},
		Cause: err,
	}
}

// TokenExchange performs an RFC 8693 token exchange via the underlying client and
// automatically maps ConsentRequiredError to *URLElicitationError when a consent
// URL is available.
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
