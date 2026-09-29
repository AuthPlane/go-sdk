// Package resource provides the Resource facade for protected resource configuration and token verification.
package resource

import (
	"encoding/json"
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

// safeErrorDescriptions maps an error code to the error_description emitted
// for it.
//
// The body is served to a caller who by definition has not authenticated, so
// error_description is built from the RFC 6750 §3.1 / RFC 9449 §7.1 error code,
// never from the error's own message. The SDK's messages name the failing
// detail — the unknown `kid`, the claim that did not validate, the `typ` that
// was rejected — and an audience mismatch in particular would hand the caller
// the exact `aud` the resource expects, which is the value they need in order
// to request a token for it. RFC 6750 §3 does not require error_description to
// be diagnostic: the error code already carries everything a conforming client
// needs in order to decide what to do next.
//
// The descriptions carry no comma, so that the same text stays safe to emit as
// a WWW-Authenticate quoted-string, where a comma separates challenge
// parameters and is what a lenient client-side parser splits on.
var safeErrorDescriptions = map[string]string{
	"invalid_token":      "The access token is missing or not valid for this resource",
	"insufficient_scope": "The access token does not carry the scope this operation requires",
	"invalid_dpop_proof": "The DPoP proof is missing or not valid for this request",
}

// marshalFallbackErrorCode is the body's `error` in the unreachable branch that
// answers a failed marshal. It names a code even where the response it replaces
// would omit one: a body carrying neither a code nor a description says less
// than a generic one.
const marshalFallbackErrorCode = "invalid_token"

// fallbackErrorDescription covers an error code with no entry in
// safeErrorDescriptions — any code added without a matching row. Kept
// deliberately contentless for the same reason the table exists.
const fallbackErrorDescription = "The request could not be authenticated"

// missingCredentialsDescription is the error_description for a request that
// presented no credentials at all.
//
// That case carries no `error` on either side. RFC 6750 §3.1 defines the codes
// for a request that did present credentials and failed, and ties
// invalid_request to a malformed request answered with 400 — a plain
// "please authenticate" 401 is neither. §3 has the challenge omit `error`
// accordingly, and the body omits it for the same reason, so a client reading
// either half of the response gets the same answer: authenticate.
const missingCredentialsDescription = "The request did not carry an access token"

// errorDescription returns the error_description value to emit for errorCode.
//
// A nil err is a programmer error — every exported entry point is documented as
// taking the error the verifier returned — but it must not panic: the
// non-verbose branch never touches err, so the verbose one guarding it keeps
// AuthErrorResponse and AuthErrorResponseVerbose agreeing on the same input.
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

// AuthErrorResponse returns the HTTP status, headers, and body for an auth error.
// An optional realm string may be passed; if non-empty it is included in the
// WWW-Authenticate challenge per RFC 6750 §3.
//
// The JSON body's error_description is a fixed, caller-safe sentence chosen by
// the error code; err's own message never reaches the wire. Log err for the
// diagnostic — it is unchanged.
//
// The challenge carries no resource_metadata parameter. Use
// AuthErrorResponseWithMetadata to advertise the RFC 9728 document, which is
// what every adapter in this SDK does.
func AuthErrorResponse(err error, realm ...string) (status int, headers map[string]string, body string) {
	return authErrorResponse(err, "", false, realm...)
}

// AuthErrorResponseVerbose is AuthErrorResponse with err's own message restored
// in the JSON error_description, which is what this package emitted before the
// description became a fixed per-code sentence.
//
// It is a development aid. The body reaches a caller who has not
// authenticated, and the SDK's messages name the failing detail — the unknown
// `kid`, the claim that did not validate, the audience the resource expects —
// so do not enable it in production. Status, headers and error code are
// identical to AuthErrorResponse either way.
func AuthErrorResponseVerbose(err error, realm ...string) (status int, headers map[string]string, body string) {
	return authErrorResponse(err, "", true, realm...)
}

// sanitizeChallengeValue strips the octets that cannot appear inside an
// RFC 9110 §11.2 quoted-string: a bare '"' terminates the parameter early and a
// '\' opens a quoted-pair a conforming client unescapes into something else,
// so either lets a caller-supplied value append auth-params of its own — a
// second resource_metadata naming a different authorization server, for
// instance. CR and LF go with them so no value can split the header.
//
// The gate in resource.New covers only what arrives through
// WithResourceMetadataURL; AuthErrorResponseWithMetadata is exported and the
// guides route custom middleware straight to it, so the emitter has to hold the
// invariant for values that never passed a constructor — the multi-tenant case
// computes the URL per request. Stripping is a no-op for anything that did pass
// the gate, so the byte-for-byte equivalence with the previous adapter
// composition is unchanged.
func sanitizeChallengeValue(v string) string {
	return strings.NewReplacer(`"`, "", "\\", "", "\r", "", "\n", "").Replace(v)
}

// AuthErrorResponseWithMetadata is AuthErrorResponse with the RFC 9728 §5.1
// resource_metadata parameter appended to the WWW-Authenticate challenge, so a
// client can discover the authorization server straight from the 401.
//
// Pass Resource.ResourceMetadataURL(); an empty resourceMetadataURL emits the
// challenge unchanged, making this a drop-in for AuthErrorResponse.
//
// The parameter goes last, after realm, error and scope, and is separated by a
// space when it is the first auth-param (the no-token case, where the challenge
// so far is the bare scheme) and by ", " otherwise — RFC 9110 §11.1 spells the
// challenge "auth-scheme 1*SP auth-param", with commas only between params.
// Adapters composed this parameter themselves until the emitter moved here;
// the bytes are unchanged, and errors_test.go pins that against the previous
// composition.
func AuthErrorResponseWithMetadata(err error, resourceMetadataURL string, realm ...string) (status int, headers map[string]string, body string) {
	return authErrorResponse(err, resourceMetadataURL, false, realm...)
}

func authErrorResponse(err error, resourceMetadataURL string, verboseDescription bool, realm ...string) (status int, headers map[string]string, body string) {
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
		wwwAuth += fmt.Sprintf(` realm="%s"`, sanitizeChallengeValue(realm[0])) //nolint:gocritic // RFC 6750 §3 requires literal double-quotes in WWW-Authenticate parameters
	}

	if errorCode != "" {
		wwwAuth += fmt.Sprintf(` error="%s"`, errorCode) //nolint:gocritic // RFC 6750 §3 requires literal double-quotes in WWW-Authenticate parameters
	}

	var scopeErr *ScopeError
	if errors.As(err, &scopeErr) && len(scopeErr.RequiredScopes) > 0 {
		wwwAuth += fmt.Sprintf(`, scope="%s"`, sanitizeChallengeValue(scopeErr.ScopeString())) //nolint:gocritic // RFC 6750 §3 requires literal double-quotes in WWW-Authenticate parameters
	}

	if resourceMetadataURL != "" {
		sep := " "
		if strings.Contains(wwwAuth, "=") {
			sep = ", "
		}
		wwwAuth += fmt.Sprintf(`%sresource_metadata="%s"`, sep, sanitizeChallengeValue(resourceMetadataURL)) //nolint:gocritic // RFC 6750 §3 requires literal double-quotes in WWW-Authenticate parameters
	}

	headers = map[string]string{
		"WWW-Authenticate": wwwAuth,
		"Content-Type":     "application/json",
	}

	// Marshaled rather than formatted with %q: strconv.Quote renders control
	// bytes as Go escapes (\a, \v, \x7f), none of which are JSON escapes
	// (RFC 8259 §7). The safe descriptions are fixed ASCII, but the verbose
	// form puts err.Error() back on the wire, and the verifier interpolates
	// token-controlled header values into those messages.
	// `error` is omitted when the challenge omits it — the missing-token case —
	// rather than being filled in with a code the header does not carry.
	bodyBytes, marshalErr := json.Marshal(struct {
		Error       string `json:"error,omitempty"`
		Description string `json:"error_description"`
	}{
		Error:       errorCode,
		Description: errorDescription(errorCode, err, verboseDescription),
	})
	if marshalErr != nil {
		// Unreachable for two strings; fall back to the fixed pair rather than
		// serve an empty body. Built from the constants so this copy cannot
		// drift from them — no test can reach this branch to catch it if it did.
		bodyBytes = fmt.Appendf(nil, `{"error":%q,"error_description":%q}`, marshalFallbackErrorCode, fallbackErrorDescription)
	}
	body = string(bodyBytes)

	return status, headers, body
}
