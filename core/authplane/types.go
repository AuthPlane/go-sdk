package authplane

import (
	"github.com/authplane/go-sdk/core/internal/oauth"
	"github.com/authplane/go-sdk/core/internal/ssrf"
)

// TokenResponse is an OAuth 2.0 token endpoint response.
type TokenResponse = oauth.TokenResponse

// IntrospectionResponse is an RFC 7662 introspection response.
type IntrospectionResponse = oauth.IntrospectionResponse

// TokenExchangeInput configures an RFC 8693 token exchange request.
type TokenExchangeInput = oauth.TokenExchangeInput

// StringOrSlice handles JSON fields that can be either a string or []string.
type StringOrSlice = oauth.StringOrSlice

// ClientAuthentication holds client-credentials style authentication settings.
type ClientAuthentication = oauth.ClientAuthentication

// ClientAuthMethod identifies the OAuth client authentication method.
type ClientAuthMethod = oauth.ClientAuthMethod

// Client authentication method constants.
const (
	ClientAuthClientSecretBasic = oauth.ClientAuthClientSecretBasic
	ClientAuthClientSecretPost  = oauth.ClientAuthClientSecretPost
)

// ConsentRequiredError is returned from TokenExchange when the authorization
// server indicates that user consent is required before the exchange can succeed.
type ConsentRequiredError = oauth.ConsentRequiredError

// FetchSettings controls SSRF protection and HTTP transport behavior for all
// outbound requests made by the SDK (metadata discovery, JWKS, token endpoint,
// introspection, revocation).
//
// Use DefaultFetchSettings or DevModeFetchSettings to obtain a baseline and
// adjust fields as needed; pass via WithFetchSettings.
type FetchSettings = ssrf.FetchSettings

// DefaultFetchSettings returns production-safe SSRF fetch settings:
// SSRF protection on, HTTPS only, no localhost, no private networks,
// 10-second timeout.
func DefaultFetchSettings() FetchSettings {
	return ssrf.DefaultFetchSettings()
}

// DevModeFetchSettings returns fetch settings with relaxed SSRF protection
// for local development: HTTP allowed, localhost and private networks allowed,
// SSRF protection still enabled to block cloud metadata addresses.
func DevModeFetchSettings() FetchSettings {
	return ssrf.DevModeFetchSettings()
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
)
