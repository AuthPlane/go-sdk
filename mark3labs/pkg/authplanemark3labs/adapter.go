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
// middleware all come from the embedded *authplanehttp.Adapter. PRM is served
// via mark3labs/mcp-go's server.NewProtectedResourceMetadataHandler so the
// HTTP framing (CORS, Cache-Control: no-store, allowed methods) matches the
// MCP authorization spec, while core remains the source of the field values.
package authplanemark3labs

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
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

// Adapter integrates the Authplane core SDK with mark3labs/mcp-go.
//
// It embeds *authplanehttp.Adapter so the standard HTTP surface — Middleware
// (Bearer + DPoP), RequireScopes, and the context helpers — is available
// directly. The mark3labs-specific additions live on Adapter itself:
// HTTPContextFunc (claims bridge), ProtectedResourceMetadataHandler (uses
// mark3labs/mcp-go's PRM handler with values from core), and TokenExchange
// with URL-elicitation mapping.
//
// Always call Close() when the adapter is no longer needed to stop background
// refresh goroutines and release HTTP connections.
type Adapter struct {
	*authplanehttp.Adapter

	client     *authplane.Client
	prmHandler http.Handler // mark3labs PRM handler, built once at construction
}

// ClaimsFromContext returns the VerifiedClaims injected by Middleware (and
// forwarded by HTTPContextFunc) into the per-tool-call context. Returns nil
// when called outside an authenticated request.
//
// Thin wrapper around authplanehttp.ClaimsFromContext — the two packages share
// a single context-key namespace so claims flow from Middleware through
// HTTPContextFunc into tool handlers without translation.
func ClaimsFromContext(ctx context.Context) *verifier.VerifiedClaims {
	return authplanehttp.ClaimsFromContext(ctx)
}

// TokenFromContext returns the raw bearer token injected by Middleware (and
// forwarded by HTTPContextFunc). Returns "" outside an authenticated request.
// Thin wrapper around authplanehttp.TokenFromContext for the same reason as
// ClaimsFromContext.
func TokenFromContext(ctx context.Context) string {
	return authplanehttp.TokenFromContext(ctx)
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

	return &Adapter{
		Adapter:    authplanehttp.New(res),
		client:     client,
		prmHandler: server.NewProtectedResourceMetadataHandler(prmConfigFromResource(res)),
	}, nil
}

// NewAdapterFromClientAndResource creates an Adapter from an already-configured
// authplane.Client and resource.Resource. Adapter.Close() still calls client.Close();
// when sharing a client across adapters, manage client lifecycle yourself and let
// the adapters go out of scope.
//
// Returns an error if client or res is nil. The signature matches the sibling
// mcp adapter — neither constructor panics, and both surface programming
// errors as a typed return value.
func NewAdapterFromClientAndResource(client *authplane.Client, res *resource.Resource) (*Adapter, error) {
	if client == nil {
		return nil, errors.New("authplanemark3labs: client must not be nil")
	}
	if res == nil {
		return nil, errors.New("authplanemark3labs: res must not be nil")
	}
	return &Adapter{
		Adapter:    authplanehttp.New(res),
		client:     client,
		prmHandler: server.NewProtectedResourceMetadataHandler(prmConfigFromResource(res)),
	}, nil
}

// AuthMiddleware returns an HTTP handler that enforces Bearer (and DPoP) token
// authentication in front of a mark3labs/mcp-go *server.StreamableHTTPServer.
//
// It is a thin wrapper over the embedded *authplanehttp.Adapter's Middleware,
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
//
// Keys with no value on the upstream context are skipped silently. For
// libraries whose context key is unexported (OpenTelemetry's span context,
// for example), use WithContextForwarding instead and copy via the library's
// own accessor.
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
//
// Multiple WithContextForwarding options compose in registration order: the
// returned context of each call is passed as mcp to the next.
//
// Use this for libraries whose context key is unexported — propagate values
// via the library's accessor (e.g. trace.ContextWithSpanContext(mcp,
// trace.SpanContextFromContext(parent))). A nil function is ignored.
func WithContextForwarding(fn func(parent, mcp context.Context) context.Context) HTTPContextOption {
	return func(c *httpContextConfig) {
		if fn != nil {
			c.mergeFns = append(c.mergeFns, fn)
		}
	}
}

// HTTPContextFunc returns a server.HTTPContextFunc that forwards the verified
// claims and raw bearer token from the HTTP request context (where the
// embedded http adapter's Middleware stored them) into the per-tool-call MCP
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

// ProtectedResourceMetadataHandler returns mark3labs/mcp-go's
// server.NewProtectedResourceMetadataHandler configured with the values from
// core's resource.PRMResponse(). The mark3labs handler handles the HTTP framing
// per the MCP authorization spec (RFC 9728): GET/HEAD/OPTIONS allowed, CORS
// headers for browser-based clients, and Cache-Control: no-store to avoid stale
// metadata during AS rotation.
//
// core remains the source of truth for the field *values* of the document, so
// they stay aligned with what other Authplane adapters advertise.
//
// The handler is built once at adapter construction and reused across calls;
// callers can safely wire it into a mux at startup without paying for repeated
// PRM config building.
//
// PRMHandler on this adapter is overridden to return the same handler, so MCP
// consumers get the right framing whether they use the mark3labs-style name
// (ProtectedResourceMetadataHandler) or the inherited authplanehttp name
// (PRMHandler). The plain-HTTP framing from authplanehttp (max-age=3600, no
// CORS) is reachable via a.Adapter.PRMHandler() if specifically needed.
func (a *Adapter) ProtectedResourceMetadataHandler() http.Handler {
	return a.prmHandler
}

// PRMHandler is overridden on the outer Adapter so callers using the inherited
// name from authplanehttp still get the mark3labs framing (CORS, no-store,
// HEAD/OPTIONS) appropriate for MCP clients. The original authplanehttp
// PRMHandler remains accessible via a.Adapter.PRMHandler() for callers that
// specifically want the plain-HTTP framing.
func (a *Adapter) PRMHandler() http.Handler {
	return a.prmHandler
}

// prmConfigFromResource maps the typed PRM config from core into mark3labs/mcp-go's
// ProtectedResourceMetadataConfig so the JSON document can be served by
// server.NewProtectedResourceMetadataHandler.
//
// Field-by-field mapping against resource.PRMConfig: when buildPRM gains a
// new RFC 9728 field, core.PRMConfig grows with it and this mapper must be
// updated explicitly — no silent drops via dynamic-map lookups.
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
//
// Do not call Close() on the returned client directly — call adapter.Close() instead,
// as the adapter owns the client lifecycle.
func (a *Adapter) Client() *authplane.Client {
	return a.client
}

// Close stops all background goroutines and releases resources held by the
// underlying client. It is safe to call multiple times.
//
// When using NewAdapterFromClientAndResource and sharing a client across multiple
// adapters, call client.Close() directly instead of adapter.Close().
func (a *Adapter) Close() error {
	return a.client.Close()
}

// defaultConsentMessage is used when ConsentRequiredError.Description is empty.
const defaultConsentMessage = "Consent is required to proceed"

// URLElicitationError carries the data for an MCP URL elicitation
// (JSON-RPC error code -32042). It is what ConsentElicitationError returns
// when it detects a consent-required error with a non-empty consent URL.
//
// mark3labs/mcp-go's tool-call error path coerces every returned error to
// JSON-RPC code -32603 (INTERNAL_ERROR), so returning a URLElicitationError
// directly from a tool handler will not propagate code -32042 to the client.
// Tool authors who need the elicitation behavior should instead return a
// CallToolResult with IsError=true and serialize the elicitation params into
// the content (see the demo). Use Code() and Params to construct that
// response. The error type is also a stable handle for errors.As inspection
// in code that calls adapter.TokenExchange directly.
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
//
// See the URLElicitationError doc comment for the mark3labs/mcp-go propagation
// caveat.
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
			ElicitationID: newUUID(),
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

// newUUID generates a random v4 UUID string without external dependencies.
// Matches the pattern in the sibling mcp adapter (mcp/pkg/authplanemcp/adapter.go).
func newUUID() string {
	var u [16]byte
	_, _ = rand.Read(u[:])      // crypto/rand.Read never returns an error on supported platforms
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
