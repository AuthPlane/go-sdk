// Package resource provides the Resource facade for protected resource configuration and token verification.
package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/authplane/go-sdk/core/resource/verifier"
)

// ScopeError wraps ErrInsufficientScope with the required scopes for WWW-Authenticate.
type ScopeError struct {
	RequiredScopes []string
	Err            error
}

func (e *ScopeError) Error() string {
	return e.Err.Error()
}

func (e *ScopeError) Unwrap() error {
	return e.Err
}

// ScopeString returns the required scopes as a space-separated string.
func (e *ScopeError) ScopeString() string {
	return strings.Join(withoutOfflineAccess(e.RequiredScopes), " ")
}

// HTTPStatus maps a verifier error to an HTTP status code.
func HTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	switch {
	case errors.Is(err, verifier.ErrInsufficientScope):
		return http.StatusForbidden
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// The caller's own context ended. The answer rarely reaches anyone.
		return http.StatusServiceUnavailable
	case errors.Is(err, verifier.ErrJWKSUnavailable),
		errors.Is(err, verifier.ErrMetadataUnavailable),
		errors.Is(err, verifier.ErrRevocationUnavailable),
		errors.Is(err, verifier.ErrDPoPReplayStoreUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, verifier.ErrTokenMissing),
		errors.Is(err, verifier.ErrTokenExpired),
		errors.Is(err, verifier.ErrInvalidSignature),
		errors.Is(err, verifier.ErrInvalidClaims),
		errors.Is(err, verifier.ErrIssuerMismatch),
		errors.Is(err, verifier.ErrAudienceMismatch),
		errors.Is(err, verifier.ErrTokenRevoked),
		errors.Is(err, verifier.ErrDPoPRequired),
		errors.Is(err, verifier.ErrDPoPNotSupported),
		errors.Is(err, verifier.ErrDPoPInvalid),
		errors.Is(err, verifier.ErrDPoPKeyMismatch),
		errors.Is(err, verifier.ErrDPoPBindingMismatch),
		errors.Is(err, verifier.ErrDPoPReplayDetected),
		errors.Is(err, verifier.ErrMultipleDpopProofs):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

// safeErrorDescriptions maps an error code to the error_description emitted
// for it.
var safeErrorDescriptions = map[string]string{
	"invalid_token":      "The access token is missing or not valid for this resource",
	"insufficient_scope": "The access token does not carry the scope this operation requires",
	"invalid_dpop_proof": "The DPoP proof is missing or not valid for this request",
	unavailableErrorCode: "The token cannot be checked right now, so retry later with the same token",
}

// marshalFallbackErrorCode is the body's `error` in the unreachable branch that
// answers a failed marshal. It names a code even where the response it replaces
// would omit one: a body carrying neither a code nor a description says less
// than a generic one.
const marshalFallbackErrorCode = "invalid_token"

const (
	// unavailableErrorCode is the body's `error` when the server could not judge the token.
	unavailableErrorCode = "temporarily_unavailable"
	// retryAfterSeconds matches the default floor between fetches after a failure.
	retryAfterSeconds = "30"
)

// fallbackErrorDescription covers an error code with no entry in
// safeErrorDescriptions — any code added without a matching row. Kept
// deliberately contentless for the same reason the table exists.
const fallbackErrorDescription = "The request could not be authenticated"

// missingCredentialsDescription is the error_description for a request that
// presented no credentials at all.
const missingCredentialsDescription = "The request did not carry an access token"

// errorDescription returns the error_description value to emit for errorCode.
//
// A nil err is a programmer error — every exported entry point is documented as
// taking the error the verifier returned — but it must not panic: the
// non-verbose branch never touches err, so the verbose one guards it.
func errorDescription(errorCode string, err error, verbose bool) string {
	if verbose && err != nil {
		return err.Error()
	}
	if errorCode == "" {
		return missingCredentialsDescription
	}
	if description, ok := safeErrorDescriptions[errorCode]; ok {
		return description
	}
	return fallbackErrorDescription
}

// ErrorOption adjusts AuthErrorResponse.
type ErrorOption func(*errorConfig)

type errorConfig struct {
	realm               string
	resourceMetadataURL string
	verbose             bool
	dpopAlgorithms      []string
	dpopRequired        bool
}

// WithRealm adds a realm to the challenge (RFC 6750 section 3).
func WithRealm(realm string) ErrorOption {
	return func(c *errorConfig) { c.realm = realm }
}

// WithChallengeMetadata advertises the RFC 9728 document in the challenge, as every adapter
// in this SDK does.
func WithChallengeMetadata(url string) ErrorOption {
	return func(c *errorConfig) { c.resourceMetadataURL = url }
}

// WithVerboseDescription puts err's own message in the JSON error_description in place of the
// fixed sentence. It is a development aid: the body reaches a caller who has not
// authenticated, and these messages name the failing detail, so do not use it in production.
func WithVerboseDescription() ErrorOption {
	return func(c *errorConfig) { c.verbose = true }
}

// WithDPoPPolicy states the resource's inbound DPoP policy: DPoP challenges list algorithms
// (RFC 9449 section 7.1), and with required set, a request with no token is told to use DPoP.
// Resource.AuthErrorResponse sets this for you.
func WithDPoPPolicy(algorithms []string, required bool) ErrorOption {
	return func(c *errorConfig) {
		c.dpopAlgorithms = algorithms
		c.dpopRequired = required
	}
}

// AuthErrorResponse returns the HTTP status, headers, and body for an auth error.
//
// The JSON body's error_description is a fixed, caller-safe sentence chosen by the error code;
// err's own message never reaches the wire unless WithVerboseDescription is set. Log err for
// the diagnostic.
func AuthErrorResponse(err error, opts ...ErrorOption) (status int, headers map[string]string, body string) {
	var cfg errorConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	status = HTTPStatus(err)
	scheme := "Bearer"
	errorCode := "invalid_token"

	switch {
	case errors.Is(err, verifier.ErrInsufficientScope):
		errorCode = "insufficient_scope"
	case errors.Is(err, verifier.ErrDPoPInvalid),
		errors.Is(err, verifier.ErrDPoPKeyMismatch),
		errors.Is(err, verifier.ErrDPoPReplayDetected),
		errors.Is(err, verifier.ErrMultipleDpopProofs):
		scheme = "DPoP"
		errorCode = "invalid_dpop_proof"
	case errors.Is(err, verifier.ErrDPoPRequired),
		errors.Is(err, verifier.ErrDPoPBindingMismatch):
		scheme = "DPoP"
	// ErrDPoPNotSupported deliberately falls through to the default "Bearer"
	// scheme: the resource does not support DPoP, so the client should retry
	// with a non-DPoP-bound token.
	case errors.Is(err, verifier.ErrTokenMissing):
		errorCode = ""
		if cfg.dpopRequired {
			scheme = "DPoP"
		}
	}

	// A failure on this side says nothing about the token. invalid_token would tell a client
	// to discard a good one, so the challenge carries no error at all.
	challengeCode := errorCode
	unavailable := status >= http.StatusInternalServerError
	if unavailable {
		errorCode, challengeCode = unavailableErrorCode, ""
	}

	// RFC 9110 section 11.3: auth-params are separated by commas.
	var params []string
	addParam := func(name, value string) {
		params = append(params, name+`="`+value+`"`)
	}
	if cfg.realm != "" {
		addParam("realm", SanitizeChallengeValue(cfg.realm))
	}
	if challengeCode != "" {
		addParam("error", challengeCode)
	}
	var scopeErr *ScopeError
	if errors.As(err, &scopeErr) && scopeErr.ScopeString() != "" {
		addParam("scope", SanitizeChallengeValue(scopeErr.ScopeString()))
	}
	if cfg.resourceMetadataURL != "" {
		addParam("resource_metadata", SanitizeChallengeValue(cfg.resourceMetadataURL))
	}
	if scheme == "DPoP" && len(cfg.dpopAlgorithms) > 0 {
		addParam("algs", SanitizeChallengeValue(strings.Join(cfg.dpopAlgorithms, " ")))
	}
	wwwAuth := scheme
	if len(params) > 0 {
		wwwAuth += " " + strings.Join(params, ", ")
	}

	headers = map[string]string{
		"WWW-Authenticate": wwwAuth,
		"Content-Type":     "application/json",
	}
	if unavailable {
		headers["Retry-After"] = retryAfterSeconds
	}

	// Marshaled rather than formatted with %q: strconv.Quote renders control bytes as Go
	// escapes, none of which are JSON escapes (RFC 8259 section 7), and the verbose form puts
	// err.Error() on the wire. `error` is omitted when the challenge omits it for a missing
	// token, rather than filled in with a code the header does not carry.
	bodyBytes, marshalErr := json.Marshal(struct {
		Error       string `json:"error,omitempty"`
		Description string `json:"error_description"`
	}{
		Error:       errorCode,
		Description: errorDescription(errorCode, err, cfg.verbose),
	})
	if marshalErr != nil {
		// Unreachable for two strings; fall back to the fixed pair rather than serve an empty body.
		bodyBytes = fmt.Appendf(nil, `{"error":%q,"error_description":%q}`, marshalFallbackErrorCode, fallbackErrorDescription)
	}
	return status, headers, string(bodyBytes)
}

// SanitizeChallengeValue makes a value safe inside an RFC 9110 quoted-string. CR, LF, a quote
// and a backslash could otherwise end the parameter or split the header, so a run of them becomes
// one space. Substitution rather than deletion keeps `a"b` two scope tokens instead of fusing it
// into one. None of these octets is legal in a scope or a URI, so no valid value changes.
func SanitizeChallengeValue(v string) string {
	return strings.TrimSpace(challengeValueSanitizer.ReplaceAllString(v, " "))
}

var challengeValueSanitizer = regexp.MustCompile(`[\r\n"\\]+`)
