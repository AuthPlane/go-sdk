package authplane

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/authplane/go-sdk/core/internal/metadata"
	"github.com/authplane/go-sdk/core/internal/oauth"
	"github.com/authplane/go-sdk/core/internal/ssrf"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/go-jose/go-jose/v4"
)

// ASMetadata is a discovered authorization server metadata document (RFC 8414 or
// OpenID Connect Discovery). Raw returns the whole document, including members with no
// typed field.
type ASMetadata struct {
	Issuer                string
	TokenEndpoint         string
	AuthorizationEndpoint string
	JWKSURI               string
	IntrospectionEndpoint string
	RevocationEndpoint    string
	RegistrationEndpoint  string

	GrantTypesSupported               []string
	ScopesSupported                   []string
	ResponseTypesSupported            []string
	TokenEndpointAuthMethodsSupported []string
	CodeChallengeMethodsSupported     []string
	DPoPSigningAlgValuesSupported     []string

	BackchannelAuthenticationEndpoint   string
	AuthorizationDetailsTypesSupported  []string
	AuthorizationGrantProfilesSupported []string

	raw func() map[string]any
}

// Raw returns the whole metadata document as decoded JSON, or nil if it cannot be decoded.
func (m *ASMetadata) Raw() map[string]any {
	if m.raw == nil {
		return nil
	}
	return m.raw()
}

func publicMetadata(m *metadata.ASMetadata) *ASMetadata {
	return &ASMetadata{
		Issuer:                              m.Issuer,
		TokenEndpoint:                       m.TokenEndpoint,
		AuthorizationEndpoint:               m.AuthorizationEndpoint,
		JWKSURI:                             m.JWKSURI,
		IntrospectionEndpoint:               m.IntrospectionEndpoint,
		RevocationEndpoint:                  m.RevocationEndpoint,
		RegistrationEndpoint:                m.RegistrationEndpoint,
		GrantTypesSupported:                 m.GrantTypesSupported,
		ScopesSupported:                     m.ScopesSupported,
		ResponseTypesSupported:              m.ResponseTypesSupported,
		TokenEndpointAuthMethodsSupported:   m.TokenEndpointAuthMethodsSupported,
		CodeChallengeMethodsSupported:       m.CodeChallengeMethodsSupported,
		DPoPSigningAlgValuesSupported:       m.DPoPSigningAlgValuesSupported,
		BackchannelAuthenticationEndpoint:   m.BackchannelAuthenticationEndpoint,
		AuthorizationDetailsTypesSupported:  m.AuthorizationDetailsTypesSupported,
		AuthorizationGrantProfilesSupported: m.AuthorizationGrantProfilesSupported,
		raw:                                 m.Raw,
	}
}

// TokenResponse is an OAuth 2.0 token endpoint response. Its String, GoString and LogValue hide
// the tokens, so it is safe to log.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`

	// ExpiresIn is nil when the server sent none. From the cache it is the time left.
	ExpiresIn *int64 `json:"expires_in,omitempty"`

	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`

	// Cnf is the raw RFC 9449 section 6.1 confirmation object, when the token is bound.
	Cnf json.RawMessage `json:"cnf,omitempty"`
	// CnfJkt is the DPoP key thumbprint from Cnf, or empty when the token is not DPoP-bound.
	CnfJkt string `json:"cnf_jkt,omitempty"`

	// AuthorizationDetails is the RFC 9396 grant the server made, as sent.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
}

// String keeps the tokens out of logs and %v.
func (r TokenResponse) String() string { return oauth.TokenResponse(r).String() }

// GoString keeps the tokens out of %#v.
func (r TokenResponse) GoString() string { return r.String() }

// LogValue keeps the tokens out of structured logs.
func (r TokenResponse) LogValue() slog.Value { return slog.StringValue(r.String()) }

// IntrospectionResponse is an RFC 7662 introspection response.
type IntrospectionResponse struct {
	Active    bool
	Scope     string
	ClientID  string
	Username  string
	TokenType string
	Issuer    string
	Subject   string
	Audience  []string
	ExpiresAt int64
	IssuedAt  int64
	JTI       string

	// AgentID and AgentChain are Authplane extensions (RFC 9706 section 3). Empty when the
	// server does not send them.
	AgentID    string
	AgentChain []string

	// Cnf is the raw confirmation object, and CnfJkt the DPoP key thumbprint from it.
	Cnf    json.RawMessage
	CnfJkt string

	// AuthorizationDetails is the RFC 9396 grant, as sent.
	AuthorizationDetails json.RawMessage

	// Extra holds members with no field here.
	Extra map[string]any
}

func publicIntrospection(r *oauth.IntrospectionResponse) *IntrospectionResponse {
	return &IntrospectionResponse{
		Active: r.Active, Scope: r.Scope, ClientID: r.ClientID, Username: r.Username, TokenType: r.TokenType,
		Issuer: r.Issuer, Subject: r.Subject, Audience: r.Audience, ExpiresAt: r.ExpiresAt, IssuedAt: r.IssuedAt,
		JTI: r.JTI, AgentID: r.AgentID, AgentChain: r.AgentChain, Cnf: r.Cnf, CnfJkt: r.CnfJkt,
		AuthorizationDetails: r.AuthorizationDetails, Extra: r.Extra,
	}
}

// ClientCredentialsInput configures a client_credentials grant.
type ClientCredentialsInput struct {
	Scopes    []string
	Resources []string
	// AuthorizationDetails is sent as RFC 9396 authorization_details. Such a request is not cached.
	AuthorizationDetails json.RawMessage
}

// JWTBearerInput configures a JWT-bearer grant. It is safe to log.
type JWTBearerInput struct {
	Assertion string
	Scopes    []string
	Resources []string
	// AuthorizationDetails is sent as RFC 9396 authorization_details.
	AuthorizationDetails json.RawMessage
}

// String keeps the assertion out of logs and %v.
func (in JWTBearerInput) String() string { return oauth.JWTBearerInput(in).String() }

// GoString keeps the assertion out of %#v.
func (in JWTBearerInput) GoString() string { return in.String() }

// LogValue keeps the assertion out of structured logs.
func (in JWTBearerInput) LogValue() slog.Value { return slog.StringValue(in.String()) }

// TokenExchangeInput configures an RFC 8693 token exchange request. It is safe to log.
type TokenExchangeInput struct {
	SubjectToken     string
	SubjectTokenType string
	ActorToken       string
	ActorTokenType   string
	Scopes           []string
	Resources        []string
	Audiences        []string
	// AuthorizationDetails is sent as RFC 9396 authorization_details. Such a request is not cached.
	AuthorizationDetails json.RawMessage
}

// String keeps the tokens out of logs and %v.
func (in TokenExchangeInput) String() string { return oauth.TokenExchangeInput(in).String() }

// GoString keeps the tokens out of %#v.
func (in TokenExchangeInput) GoString() string { return in.String() }

// LogValue keeps the tokens out of structured logs.
func (in TokenExchangeInput) LogValue() slog.Value { return slog.StringValue(in.String()) }

// ClientAuthMethod identifies the OAuth client authentication method.
type ClientAuthMethod string

// Client authentication method constants.
const (
	ClientAuthClientSecretBasic ClientAuthMethod = ClientAuthMethod(oauth.ClientAuthClientSecretBasic)
	ClientAuthClientSecretPost  ClientAuthMethod = ClientAuthMethod(oauth.ClientAuthClientSecretPost)
	ClientAuthPrivateKeyJWT     ClientAuthMethod = ClientAuthMethod(oauth.ClientAuthPrivateKeyJWT)
)

// ClientAuthentication holds client-credentials style authentication settings. It is safe to log.
type ClientAuthentication struct {
	Method       ClientAuthMethod
	ClientID     string
	ClientSecret string

	// SigningKey, SigningAlg and KeyID sign the assertion for ClientAuthPrivateKeyJWT.
	// SigningAlg must be asymmetric.
	SigningKey crypto.Signer
	SigningAlg jose.SignatureAlgorithm
	KeyID      string

	// AssertionAudienceTokenEndpoint uses the token endpoint as the assertion's aud in place of
	// the issuer, for servers that demand it. Only assertions sent to the token endpoint use it:
	// one sent elsewhere could be replayed there by whoever receives it.
	AssertionAudienceTokenEndpoint bool
}

func (a ClientAuthentication) internal() oauth.ClientAuthentication {
	return oauth.ClientAuthentication{
		Method:                         oauth.ClientAuthMethod(a.Method),
		ClientID:                       a.ClientID,
		ClientSecret:                   a.ClientSecret,
		SigningKey:                     a.SigningKey,
		SigningAlg:                     a.SigningAlg,
		KeyID:                          a.KeyID,
		AssertionAudienceTokenEndpoint: a.AssertionAudienceTokenEndpoint,
	}
}

// String keeps the client secret and signing key out of logs and %v.
func (a ClientAuthentication) String() string { return a.internal().String() }

// GoString keeps secrets out of %#v.
func (a ClientAuthentication) GoString() string { return a.String() }

// LogValue keeps secrets out of structured logs.
func (a ClientAuthentication) LogValue() slog.Value { return slog.StringValue(a.String()) }

// MarshalJSON keeps secrets out of JSON.
func (a ClientAuthentication) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Method   ClientAuthMethod
		ClientID string
	}{a.Method, a.ClientID})
}

// ConsentRequiredError is returned from TokenExchange when the authorization
// server indicates that user consent is required before the exchange can succeed.
type ConsentRequiredError = oauth.ConsentRequiredError

// OAuthError is an error answer from the authorization server, for errors.As. It wraps the
// matching sentinel, so errors.Is works too.
type OAuthError = oauth.ResponseError

// FetchSettings controls SSRF protection and HTTP behavior for all outbound requests the SDK
// makes (metadata discovery, JWKS, token endpoint, introspection, revocation). Pass it with
// WithFetchSettings.
//
// The zero value is the safe one: protection on, https only, public addresses only.
type FetchSettings struct {
	// DisableSSRFProtection skips DNS pinning and address checks. Never set it in production.
	DisableSSRFProtection bool
	// AllowHTTP permits http:// URLs.
	AllowHTTP bool
	// AllowLocalhost permits loopback addresses.
	AllowLocalhost bool
	// AllowPrivateNets permits private address ranges.
	AllowPrivateNets bool
	// Timeout bounds each request. Zero means ten seconds.
	Timeout time.Duration
	// Proxy chooses a proxy for each request, such as http.ProxyFromEnvironment. Nil means none.
	// Addresses are still checked and pinned here, and the SDK never reads a proxy from the
	// environment by itself.
	Proxy func(*http.Request) (*url.URL, error)
	// UserAgent is sent on every fetch. Empty sends the SDK's own.
	UserAgent string
	// Observe, when set, is called after every fetch, for metrics. It must not block.
	Observe func(FetchEvent)
	// RootCAs replaces the system trust store for every fetch, for a server behind a private CA.
	RootCAs *x509.CertPool
}

// FetchEvent describes a completed fetch. Its fields hold no query or body. Err may name the
// request path, so treat it as you would a log line.
type FetchEvent struct {
	Method   string
	Host     string
	Status   int // zero if no response arrived
	Duration time.Duration
	Err      error
}

func (f FetchSettings) internal() ssrf.FetchSettings {
	settings := ssrf.FetchSettings{
		DisableSSRFProtection: f.DisableSSRFProtection,
		AllowHTTP:             f.AllowHTTP,
		AllowLocalhost:        f.AllowLocalhost,
		AllowPrivateNets:      f.AllowPrivateNets,
		Timeout:               f.Timeout,
		Proxy:                 f.Proxy,
		UserAgent:             f.UserAgent,
		RootCAs:               f.RootCAs,
	}
	if f.Observe != nil {
		settings.Observe = func(e ssrf.FetchEvent) { f.Observe(FetchEvent(e)) }
	}
	return settings
}

// DefaultFetchSettings returns production-safe settings: protection on, HTTPS only, no localhost,
// no private networks, ten-second timeout.
func DefaultFetchSettings() FetchSettings {
	return FetchSettings{Timeout: ssrf.DefaultTimeout}
}

// DevModeFetchSettings returns settings for local development: HTTP, localhost and private
// networks allowed, with protection still on so cloud metadata addresses stay blocked.
func DevModeFetchSettings() FetchSettings {
	dev := ssrf.DevModeFetchSettings()
	return FetchSettings{
		AllowHTTP:        dev.AllowHTTP,
		AllowLocalhost:   dev.AllowLocalhost,
		AllowPrivateNets: dev.AllowPrivateNets,
		Timeout:          dev.Timeout,
	}
}

// OAuth 2.0 error sentinels re-exported from internal/oauth.
var (
	ErrInvalidGrant         = oauth.ErrInvalidGrant
	ErrInvalidScope         = oauth.ErrInvalidScope
	ErrInvalidClient        = oauth.ErrInvalidClient
	ErrUnauthorizedClient   = oauth.ErrUnauthorizedClient
	ErrUnsupportedGrantType = oauth.ErrUnsupportedGrantType
	ErrInvalidRequest       = oauth.ErrInvalidRequest
	ErrServerError          = oauth.ErrServerError
	ErrCircuitOpen          = oauth.ErrCircuitOpen
	ErrProtocolError        = oauth.ErrProtocolError
	ErrUseDPoPNonce         = oauth.ErrUseDPoPNonce
	ErrConsentRequired      = oauth.ErrConsentRequired
	ErrInteractionRequired  = oauth.ErrInteractionRequired
	ErrAccessDenied         = oauth.ErrAccessDenied
	ErrInvalidTarget        = oauth.ErrInvalidTarget

	// ErrSSRFBlocked: the fetch guard refused a URL or every address it resolved to.
	ErrSSRFBlocked = ssrf.ErrSSRFBlocked
	// ErrDNSResolution: a host name did not resolve. Says nothing about the guard.
	ErrDNSResolution = ssrf.ErrDNSResolution
	// ErrNoIntrospectionEndpoint: the server's metadata has no introspection_endpoint.
	ErrNoIntrospectionEndpoint = oauth.ErrNoIntrospectionEndpoint
	// ErrMetadataUnavailable: the server's metadata could not be fetched or was refused.
	ErrMetadataUnavailable = verifier.ErrMetadataUnavailable
	// ErrCredentialsNotConfigured: a call needs client credentials the Client was not given.
	ErrCredentialsNotConfigured = errors.New("authplane: client credentials not configured")
	// ErrClientClosed: the Client has been closed.
	ErrClientClosed = errors.New("authplane: client closed")
)
