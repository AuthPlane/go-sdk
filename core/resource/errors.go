// Package resource provides the Resource facade for protected resource configuration and token verification.
package resource

import (
	"errors"
	"fmt"
	"net/http"
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
	return strings.Join(e.RequiredScopes, " ")
}

// HTTPStatus maps a verifier error to an HTTP status code.
func HTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	switch {
	case errors.Is(err, verifier.ErrInsufficientScope):
		return http.StatusForbidden
	case errors.Is(err, verifier.ErrJWKSUnavailable),
		errors.Is(err, verifier.ErrMetadataUnavailable):
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
	case errors.Is(err, verifier.ErrSSRFBlocked),
		errors.Is(err, verifier.ErrProtocolError):
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// AuthErrorResponse returns the HTTP status, headers, and body for an auth error.
// An optional realm string may be passed; if non-empty it is included in the
// WWW-Authenticate challenge per RFC 6750 §3.
func AuthErrorResponse(err error, realm ...string) (status int, headers map[string]string, body string) {
	status = HTTPStatus(err)
	scheme := "Bearer"
	errorCode := "invalid_token"

	switch {
	case errors.Is(err, verifier.ErrInsufficientScope):
		errorCode = "insufficient_scope"
	case errors.Is(err, verifier.ErrDPoPRequired),
		errors.Is(err, verifier.ErrDPoPInvalid),
		errors.Is(err, verifier.ErrDPoPKeyMismatch),
		errors.Is(err, verifier.ErrDPoPBindingMismatch),
		errors.Is(err, verifier.ErrDPoPReplayDetected):
		scheme = "DPoP"
	case errors.Is(err, verifier.ErrMultipleDpopProofs):
		// RFC 9449 §7.1 prescribes invalid_dpop_proof for §4.3 rejections,
		// not the SDK's historical invalid_token used by the other ErrDPoP*
		// shapes. Scoped to this error; a broader sweep is a separate change.
		scheme = "DPoP"
		errorCode = "invalid_dpop_proof"
	// ErrDPoPNotSupported deliberately falls through to the default "Bearer"
	// scheme: the resource does not support DPoP, so the client should retry
	// with a non-DPoP-bound token.
	case errors.Is(err, verifier.ErrTokenMissing):
		errorCode = ""
	}

	wwwAuth := scheme

	// RFC 6750 §3: realm SHOULD be included in challenges.
	if len(realm) > 0 && realm[0] != "" {
		wwwAuth += fmt.Sprintf(` realm="%s"`, realm[0]) //nolint:gocritic // RFC 6750 §3 requires literal double-quotes in WWW-Authenticate parameters
	}

	if errorCode != "" {
		wwwAuth += fmt.Sprintf(` error="%s"`, errorCode) //nolint:gocritic // RFC 6750 §3 requires literal double-quotes in WWW-Authenticate parameters
	}

	var scopeErr *ScopeError
	if errors.As(err, &scopeErr) && len(scopeErr.RequiredScopes) > 0 {
		wwwAuth += fmt.Sprintf(`, scope="%s"`, scopeErr.ScopeString()) //nolint:gocritic // RFC 6750 §3 requires literal double-quotes in WWW-Authenticate parameters
	}

	headers = map[string]string{
		"WWW-Authenticate": wwwAuth,
		"Content-Type":     "application/json",
	}

	if errorCode == "" {
		body = fmt.Sprintf(`{"error":"invalid_request","error_description":%q}`, err.Error())
	} else {
		body = fmt.Sprintf(`{"error":%q,"error_description":%q}`, errorCode, err.Error())
	}

	return status, headers, body
}
