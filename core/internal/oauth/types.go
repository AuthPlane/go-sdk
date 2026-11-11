package oauth

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// ClientAuthMethod identifies the OAuth client authentication method.
type ClientAuthMethod string

// Client authentication method constants.
const (
	ClientAuthClientSecretBasic ClientAuthMethod = "client_secret_basic"
	ClientAuthClientSecretPost  ClientAuthMethod = "client_secret_post"
	ClientAuthPrivateKeyJWT     ClientAuthMethod = "private_key_jwt"
)

// flexibleInt64 reads a JSON number, or a number in a string, which some servers send for
// expires_in.
type flexibleInt64 int64

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexibleInt64) UnmarshalJSON(data []byte) error {
	text := strings.Trim(string(data), `"`)
	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return fmt.Errorf("expires_in is not a number: %w", err)
	}
	*f = flexibleInt64(value)
	return nil
}

// ClientAuthentication holds client-credentials style authentication settings.
type ClientAuthentication struct {
	Method       ClientAuthMethod
	ClientID     string
	ClientSecret string

	// SigningKey, SigningAlg and KeyID sign the assertion for ClientAuthPrivateKeyJWT.
	// SigningAlg must be asymmetric.
	SigningKey crypto.Signer
	SigningAlg jose.SignatureAlgorithm
	KeyID      string

	// AssertionAudienceTokenEndpoint uses the token endpoint as the assertion's aud,
	// for servers that demand it, such as Microsoft Entra ID, in place of the issuer. Only assertions sent to the
	// token endpoint use it: one sent elsewhere could be replayed there by whoever
	// receives it (draft-ietf-oauth-rfc7523bis).
	AssertionAudienceTokenEndpoint bool

	issuer string // the assertion's default aud; see BindIssuer
}

// BindIssuer returns auth with the issuer its assertions name by default. The client
// facade calls it, so callers never set this themselves.
func BindIssuer(auth ClientAuthentication, issuer string) ClientAuthentication {
	auth.issuer = issuer
	return auth
}

// StringOrSlice handles JSON fields that can be either a string or []string.
type StringOrSlice []string

// UnmarshalJSON implements json.Unmarshaler for StringOrSlice.
func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = StringOrSlice{str}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*s = StringOrSlice(arr)
	return nil
}

// TokenResponse represents an OAuth 2.0 token endpoint response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`

	// ExpiresIn is `*int64` so the wire shape `expires_in: 0` (RFC 6749
	// §5.1 — a deliberately-expired one-shot token) is distinguishable
	// from the field being absent. Cache callers honor the AS's intent:
	// nil ⇒ apply the default TTL; `*v == 0` ⇒ refuse to store.
	ExpiresIn *int64 `json:"expires_in,omitempty"`

	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`

	// Cnf is the raw RFC 9449 §6.1 confirmation object from the token
	// response when present. Preserves extension members (`x5t#S256`,
	// future RFC 9449 additions) verbatim. Nil when the AS did not emit
	// `cnf`, or when the value was a non-object scalar (NormalizeCnf
	// drops malformed inputs to keep the typed shape honest).
	Cnf json.RawMessage `json:"cnf,omitempty"`

	// CnfJkt is the convenience accessor for the DPoP key thumbprint at
	// `cnf.jkt` (RFC 9449 §6.1). Empty string when the token is not
	// DPoP-bound. Always derived from `cnf.jkt` at parse time (see
	// NormalizeCnf), so a wire payload that pinned a top-level `cnf_jkt`
	// disagreeing with its own `cnf.jkt` cannot mint a mismatched
	// thumbprint.
	CnfJkt string `json:"cnf_jkt,omitempty"`

	// AuthorizationDetails is the RFC 9396 authorization_details the server granted.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
}

// IntrospectionResponse represents an RFC 7662 introspection response.
type IntrospectionResponse struct {
	Active    bool          `json:"active"`
	Scope     string        `json:"scope,omitempty"`
	ClientID  string        `json:"client_id,omitempty"`
	Username  string        `json:"username,omitempty"`
	TokenType string        `json:"token_type,omitempty"`
	Issuer    string        `json:"iss,omitempty"`
	Subject   string        `json:"sub,omitempty"`
	Audience  StringOrSlice `json:"aud,omitempty"`
	ExpiresAt int64         `json:"exp,omitempty"`
	IssuedAt  int64         `json:"iat,omitempty"`
	JTI       string        `json:"jti,omitempty"`

	// AgentID is an AuthPlane extension identifying the agent that minted
	// or relayed the token (RFC 9706 §3). Empty when the AS does not emit it.
	AgentID string `json:"agent_id,omitempty"`

	// AgentChain is an AuthPlane extension carrying the ordered chain of
	// agents that have acted on this token, root first (RFC 9706 §3). Empty
	// when the AS does not emit it.
	AgentChain []string `json:"agent_chain,omitempty"`

	// Cnf is the raw RFC 9449 §6.2 / RFC 7662 confirmation object.
	// Same semantics as TokenResponse.Cnf — preserved verbatim when the
	// AS sent a JSON object; nil otherwise.
	Cnf json.RawMessage `json:"cnf,omitempty"`

	// CnfJkt is the DPoP key thumbprint at `cnf.jkt` (RFC 9449 §6.2).
	// Same derivation semantics as TokenResponse.CnfJkt.
	CnfJkt string `json:"cnf_jkt,omitempty"`

	// AuthorizationDetails is the token's RFC 9396 authorization_details.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`

	// Extra captures unknown claims from the introspection response.
	Extra map[string]any `json:"-"`
}

// ClientCredentialsInput configures a client_credentials grant.
type ClientCredentialsInput struct {
	Scopes    []string
	Resources []string

	// AuthorizationDetails is a JSON array sent as RFC 9396 authorization_details.
	AuthorizationDetails json.RawMessage
}

// JWTBearerInput configures an RFC 7523 section 2.1 JWT-bearer grant, which also
// redeems an Identity Assertion JWT Authorization Grant (ID-JAG).
type JWTBearerInput struct {
	Assertion string
	Scopes    []string
	Resources []string

	// AuthorizationDetails is a JSON array sent as RFC 9396 authorization_details.
	AuthorizationDetails json.RawMessage
}

// TokenExchangeInput configures an RFC 8693 token exchange request.
type TokenExchangeInput struct {
	SubjectToken     string
	SubjectTokenType string
	ActorToken       string
	ActorTokenType   string
	Scopes           []string
	Resources        []string
	Audiences        []string

	// AuthorizationDetails is a JSON array sent as RFC 9396 authorization_details.
	AuthorizationDetails json.RawMessage
}

// ConsentRequiredError is returned from token exchange when the authorization
// server indicates that user consent is required before the exchange can succeed.
// The AS may include a consent URL and description in its error response.
type ConsentRequiredError struct {
	// ConsentURL is the URL the user should visit to grant consent.
	// May be empty if the AS does not provide it.
	ConsentURL string

	// Description is a human-readable explanation from the AS error_description field.
	Description string

	// Cause is the underlying OAuth error (consent_required or interaction_required).
	Cause error
}

func (e *ConsentRequiredError) Error() string {
	msg := "auth: consent required"
	if e.Description != "" {
		msg += ": " + e.Description
	}
	return msg
}

func (e *ConsentRequiredError) Unwrap() error {
	return e.Cause
}

// ResponseError is an error answer from the authorization server. It wraps the matching
// sentinel, so errors.Is still works, and errors.As gives the server's code and status.
type ResponseError struct {
	// Code is the RFC 6749 error code, or empty if the body held none.
	Code string
	// Description is the server's error_description, cleaned and shortened.
	Description string
	// Status is the HTTP status of the answer.
	Status int
	// RetryAfter is the delay the Retry-After header asked for in seconds form, or zero.
	RetryAfter time.Duration

	cause error
}

func (e *ResponseError) Error() string {
	switch {
	case e.cause != nil && e.Description != "":
		return e.cause.Error() + ": " + e.Description
	case e.cause != nil:
		return e.cause.Error()
	case e.Description != "":
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Description)
	default:
		return fmt.Sprintf("HTTP %d", e.Status)
	}
}

// Unwrap returns the sentinel for Code.
func (e *ResponseError) Unwrap() error { return e.cause }

// OAuth 2.0 error sentinels.
var (
	ErrInvalidGrant         = errors.New("auth: invalid_grant")
	ErrInvalidScope         = errors.New("auth: invalid_scope")
	ErrInvalidClient        = errors.New("auth: invalid_client")
	ErrUnauthorizedClient   = errors.New("auth: unauthorized_client")
	ErrUnsupportedGrantType = errors.New("auth: unsupported_grant_type")
	ErrInvalidRequest       = errors.New("auth: invalid_request")
	ErrServerError          = errors.New("auth: server_error")
	ErrProtocolError        = errors.New("auth: protocol_error")
	ErrCircuitOpen          = errors.New("auth: circuit open")
	// ErrNoIntrospectionEndpoint: the server's metadata has no introspection_endpoint.
	ErrNoIntrospectionEndpoint = fmt.Errorf("%w: introspection endpoint not configured", ErrInvalidRequest)
	ErrUseDPoPNonce            = errors.New("auth: use_dpop_nonce")
	ErrConsentRequired         = errors.New("auth: consent_required")
	ErrInteractionRequired     = errors.New("auth: interaction_required")
	// ErrAccessDenied is returned when the AS refuses a cross-client token
	// exchange (HTTP 403): the exchanging client is not allowlisted on the
	// target resource. Operator-fixable, not user-fixable — re-prompting the
	// user does not help, unlike consent_required.
	ErrAccessDenied = errors.New("auth: access_denied")
	// ErrInvalidTarget is returned when the requested resource does not match
	// a granted resource byte for byte (RFC 8707 §2.2; a trailing slash counts).
	ErrInvalidTarget = errors.New("auth: invalid_target")
)

// mapOAuthError maps an OAuth 2.0 error code string to a sentinel error.
func mapOAuthError(errorCode string) error {
	switch errorCode {
	case "invalid_grant":
		return ErrInvalidGrant
	case "invalid_scope":
		return ErrInvalidScope
	case "invalid_client":
		return ErrInvalidClient
	case "unauthorized_client":
		return ErrUnauthorizedClient
	case "unsupported_grant_type":
		return ErrUnsupportedGrantType
	case "invalid_request":
		return ErrInvalidRequest
	case "server_error":
		return ErrServerError
	case "use_dpop_nonce":
		return ErrUseDPoPNonce
	case "consent_required":
		return ErrConsentRequired
	case "interaction_required":
		return ErrInteractionRequired
	case "access_denied":
		return ErrAccessDenied
	case "invalid_target":
		return ErrInvalidTarget
	default:
		return errors.New("auth: " + cleanServerText([]byte(errorCode)))
	}
}
