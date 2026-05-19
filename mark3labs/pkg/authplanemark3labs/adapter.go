// Package authplanemark3labs is the Authplane adapter for the mark3labs/mcp-go
// server library.
//
// It validates OAuth 2.1 JWT access tokens on incoming HTTP requests, serves
// RFC 9728 Protected Resource Metadata, bridges verified claims into the
// per-tool-call context that mark3labs/mcp-go exposes through
// server.WithHTTPContextFunc, and maps RFC 8693 token-exchange consent errors
// to the MCP URL elicitation shape (JSON-RPC -32042).
package authplanemark3labs

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// claimsKey is the context key used to store VerifiedClaims for downstream handlers.
type claimsKey struct{}

// tokenKey is the context key used to store the raw bearer token for downstream handlers.
type tokenKey struct{}

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

// Adapter provides authentication middleware, an HTTPContextFunc bridge, and
// PRM handlers for integrating the Authplane core SDK with the mark3labs/mcp-go
// streamable HTTP server.
//
// Always call Close() when the adapter is no longer needed to stop background
// refresh goroutines and release HTTP connections.
type Adapter struct {
	client   *authplane.Client
	resource *resource.Resource
	prmURL   string // full URL advertised in the WWW-Authenticate resource_metadata param
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

	resourceURL, err := url.Parse(options.Resource)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("authplane-mark3labs: invalid resource URL: %w", err)
	}
	prmURL := resourceURL.ResolveReference(&url.URL{Path: res.WellKnownPRMPath()}).String()

	return &Adapter{
		client:   client,
		resource: res,
		prmURL:   prmURL,
	}, nil
}

// NewAdapterFromClientAndResource creates an Adapter from an already-configured
// authplane.Client and resource.Resource. Adapter.Close() still calls client.Close();
// when sharing a client across adapters, manage client lifecycle yourself and let
// the adapters go out of scope.
func NewAdapterFromClientAndResource(client *authplane.Client, res *resource.Resource) (*Adapter, error) {
	resourceURL, err := url.Parse(res.URI())
	if err != nil {
		return nil, fmt.Errorf("authplane-mark3labs: invalid resource URL: %w", err)
	}
	prmURL := resourceURL.ResolveReference(&url.URL{Path: res.WellKnownPRMPath()}).String()

	return &Adapter{
		client:   client,
		resource: res,
		prmURL:   prmURL,
	}, nil
}

// AuthMiddleware returns an HTTP handler that enforces bearer-token authentication
// in front of a mark3labs/mcp-go *server.StreamableHTTPServer.
//
// On failure it writes a 401 with an RFC 6750 §3.1 compliant WWW-Authenticate
// header pointing to the Protected Resource Metadata URL, so MCP clients can
// auto-discover the authorization server.
//
// On success the verified claims and raw token are stored in the *request*
// context. To forward them into the per-tool-call MCP context (which
// mark3labs/mcp-go derives via WithHTTPContextFunc), wire HTTPContextFunc()
// when constructing the streamable server. Scope enforcement is per-tool —
// individual tool handlers call ClaimsFromContext(ctx).RequireScope(...).
func (a *Adapter) AuthMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := extractBearer(r.Header.Get("Authorization"))
		if !ok {
			a.writeUnauthorized(w, "", "Bearer token required")
			return
		}

		claims, err := a.resource.VerifyToken(r.Context(), token)
		if err != nil {
			a.writeUnauthorized(w, "invalid_token", err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey{}, claims)
		ctx = context.WithValue(ctx, tokenKey{}, token)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractBearer parses the Authorization header and returns the bearer token,
// or ("", false) if the scheme is missing or not Bearer. Comparison of the
// scheme is case-insensitive per RFC 7235 §2.1.
func extractBearer(header string) (string, bool) {
	scheme, rest, ok := strings.Cut(header, " ")
	if !ok {
		return "", false
	}
	if !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(rest)
	if token == "" {
		return "", false
	}
	return token, true
}

// writeUnauthorized writes a 401 with an RFC 6750 §3.1 compliant
// WWW-Authenticate: Bearer challenge. resource_metadata always carries the
// PRM URL; when errCode is non-empty it is included with errDescription
// (quoted, no double-quotes in the description).
func (a *Adapter) writeUnauthorized(w http.ResponseWriter, errCode, errDescription string) {
	var b strings.Builder
	b.WriteString(`Bearer resource_metadata="`)
	b.WriteString(a.prmURL)
	b.WriteString(`"`)
	if errCode != "" {
		b.WriteString(`, error="`)
		b.WriteString(errCode)
		b.WriteString(`"`)
		if errDescription != "" {
			b.WriteString(`, error_description="`)
			b.WriteString(sanitizeQuoted(errDescription))
			b.WriteString(`"`)
		}
	}
	w.Header().Set("WWW-Authenticate", b.String())
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// sanitizeQuoted removes any characters that would break a quoted-string
// auth-param value: backslash and double-quote (RFC 7230 §3.2.6). Newlines are
// also stripped so a verifier error message cannot inject extra header lines.
func sanitizeQuoted(s string) string {
	r := strings.NewReplacer(`"`, "'", `\`, "/", "\r", " ", "\n", " ")
	return r.Replace(s)
}

// HTTPContextFunc returns a server.HTTPContextFunc that forwards the verified
// claims and raw bearer token from the HTTP request context (where
// AuthMiddleware stored them) into the per-tool-call MCP context.
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
func (a *Adapter) HTTPContextFunc() server.HTTPContextFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		if claims, ok := r.Context().Value(claimsKey{}).(*verifier.VerifiedClaims); ok && claims != nil {
			ctx = context.WithValue(ctx, claimsKey{}, claims)
		}
		if token, ok := r.Context().Value(tokenKey{}).(string); ok && token != "" {
			ctx = context.WithValue(ctx, tokenKey{}, token)
		}
		return ctx
	}
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

// TokenFromContext returns the raw bearer token injected by AuthMiddleware (and
// forwarded by HTTPContextFunc) into the request context. Returns an empty
// string if called outside an authenticated request.
//
//	token := authplanemark3labs.TokenFromContext(ctx)
//	err := adapter.Client().Revoke(ctx, token)
func TokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(tokenKey{}).(string)
	return token
}

// ClaimsFromContext returns the VerifiedClaims injected by AuthMiddleware (and
// forwarded by HTTPContextFunc) into the per-tool-call context.
//
//	claims := authplanemark3labs.ClaimsFromContext(ctx)
//	if err := claims.RequireScope("tools/add"); err != nil {
//	    return mcp.NewToolResultErrorFromErr("forbidden", err), nil
//	}
func ClaimsFromContext(ctx context.Context) *verifier.VerifiedClaims {
	claims, _ := ctx.Value(claimsKey{}).(*verifier.VerifiedClaims)
	return claims
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
// Tool authors who need the elicitation behaviour should instead return a
// CallToolResult with IsError=true and serialise the elicitation params into
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
func newUUID() string {
	var u [16]byte
	_, _ = rand.Read(u[:])      // crypto/rand.Read never returns an error on supported platforms
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
