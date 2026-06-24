// Package oauth implements OAuth 2.0 client operations (token exchange, introspection, revocation).
package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/authplane/go-sdk/core/internal/ssrf"
)

// ValidateClientAuthentication validates client-credentials style auth settings.
func ValidateClientAuthentication(auth ClientAuthentication) error {
	auth.ClientID = strings.TrimSpace(auth.ClientID)
	auth.ClientSecret = strings.TrimSpace(auth.ClientSecret)
	if auth.ClientID == "" {
		return fmt.Errorf("%w: client_id must not be empty", ErrInvalidRequest)
	}
	if auth.ClientSecret == "" {
		return fmt.Errorf("%w: client_secret must not be empty", ErrInvalidRequest)
	}
	switch auth.Method {
	case ClientAuthClientSecretBasic, ClientAuthClientSecretPost:
		return nil
	case "":
		return fmt.Errorf("%w: client auth method must not be empty", ErrInvalidRequest)
	default:
		return fmt.Errorf("%w: unsupported client auth method %q", ErrInvalidRequest, auth.Method)
	}
}

func basicAuth(auth ClientAuthentication) string {
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(auth.ClientID)+":"+url.QueryEscape(auth.ClientSecret)),
	)
}

func applyClientAuthentication(auth ClientAuthentication, form url.Values, headers http.Header) error {
	if err := ValidateClientAuthentication(auth); err != nil {
		return err
	}
	switch auth.Method {
	case ClientAuthClientSecretBasic:
		headers.Set("Authorization", basicAuth(auth))
	case ClientAuthClientSecretPost:
		form.Set("client_id", auth.ClientID)
		form.Set("client_secret", auth.ClientSecret)
	default:
		return fmt.Errorf("%w: unsupported client auth method %q", ErrInvalidRequest, auth.Method)
	}
	return nil
}

// NormalizeScopeValues trims, drops empties, and sorts scopes into canonical order.
func NormalizeScopeValues(scopes []string) []string {
	values := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			values = append(values, scope)
		}
	}
	sort.Strings(values)
	return values
}

// NormalizeRequestValues trims, drops empties, and sorts repeated request values.
func NormalizeRequestValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func normalizedScopeString(scopes []string) string {
	return strings.Join(NormalizeScopeValues(scopes), " ")
}

// ClientCredentials performs a client_credentials grant.
func ClientCredentials(ctx context.Context, endpoint string, auth ClientAuthentication, fetchSettings ssrf.FetchSettings, scopes, resources []string, dpop DPoPProvider) (*TokenResponse, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("%w: token endpoint not configured", ErrInvalidRequest)
	}

	form := url.Values{
		"grant_type": {"client_credentials"},
	}
	scope := normalizedScopeString(scopes)
	if scope != "" {
		form.Set("scope", scope)
	}
	for _, resource := range NormalizeRequestValues(resources) {
		form.Add("resource", resource)
	}

	return doTokenRequest(ctx, endpoint, auth, fetchSettings, form, dpop)
}

// TokenExchange performs an RFC 8693 token exchange.
func TokenExchange(ctx context.Context, endpoint string, auth ClientAuthentication, fetchSettings ssrf.FetchSettings, in TokenExchangeInput, dpop DPoPProvider) (*TokenResponse, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("%w: token endpoint not configured", ErrInvalidRequest)
	}

	subjectToken := strings.TrimSpace(in.SubjectToken)
	if subjectToken == "" {
		return nil, fmt.Errorf("%w: subject_token must not be empty", ErrInvalidRequest)
	}

	form := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token": {subjectToken},
	}

	subjectTokenType := strings.TrimSpace(in.SubjectTokenType)
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}
	form.Set("subject_token_type", subjectTokenType)

	if actorToken := strings.TrimSpace(in.ActorToken); actorToken != "" {
		form.Set("actor_token", actorToken)
		actorType := strings.TrimSpace(in.ActorTokenType)
		if actorType == "" {
			actorType = "urn:ietf:params:oauth:token-type:access_token"
		}
		form.Set("actor_token_type", actorType)
	}

	scope := normalizedScopeString(in.Scopes)
	if scope != "" {
		form.Set("scope", scope)
	}
	for _, resource := range NormalizeRequestValues(in.Resources) {
		form.Add("resource", resource)
	}
	for _, audience := range NormalizeRequestValues(in.Audiences) {
		form.Add("audience", audience)
	}

	resp, err := doTokenRequest(ctx, endpoint, auth, fetchSettings, form, dpop)
	if err != nil {
		return nil, err
	}

	// RFC 8693 §2.2.1: issued_token_type is REQUIRED in token exchange responses.
	if resp.IssuedTokenType == "" {
		return nil, fmt.Errorf("%w: missing required field \"issued_token_type\" in token exchange response", ErrProtocolError)
	}

	return resp, nil
}

// Introspect performs an RFC 7662 token introspection.
func Introspect(ctx context.Context, endpoint string, auth ClientAuthentication, fetchSettings ssrf.FetchSettings, token string, dpop DPoPProvider) (*IntrospectionResponse, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("%w: introspection endpoint not configured", ErrInvalidRequest)
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("%w: token must not be empty", ErrInvalidRequest)
	}

	form := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}

	resp, err := postForm(ctx, endpoint, auth, fetchSettings, form, "introspection request failed", dpop)
	if err != nil {
		return nil, err
	}

	if resp.Status < 200 || resp.Status >= 300 {
		return nil, parseErrorResponse(resp.Body, resp.Status)
	}

	var result IntrospectionResponse
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("introspection: invalid JSON response: %w", err)
	}

	NormalizeCnf(&result.Cnf, &result.CnfJkt)

	// Parse extra fields.
	var rawMap map[string]any
	if err := json.Unmarshal(resp.Body, &rawMap); err == nil {
		known := map[string]bool{
			"active": true, "scope": true, "client_id": true, "username": true,
			"token_type": true, "iss": true, "sub": true, "aud": true,
			"exp": true, "iat": true, "jti": true,
			// AuthPlane extensions surfaced as first-class fields (RFC 9706).
			"agent_id": true, "agent_chain": true,
			// RFC 9449 §6.2 — confirmation. Surfaced first-class above so
			// it must not also land in Extra.
			"cnf": true, "cnf_jkt": true,
		}
		extra := make(map[string]any)
		for k, v := range rawMap {
			if !known[k] {
				extra[k] = v
			}
		}
		if len(extra) > 0 {
			result.Extra = extra
		}
	}

	return &result, nil
}

// Revoke performs an RFC 7009 token revocation.
func Revoke(ctx context.Context, endpoint string, auth ClientAuthentication, fetchSettings ssrf.FetchSettings, token string, dpop DPoPProvider) error {
	if endpoint == "" {
		return fmt.Errorf("%w: revocation endpoint not configured", ErrInvalidRequest)
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("%w: token must not be empty", ErrInvalidRequest)
	}

	form := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}

	resp, err := postForm(ctx, endpoint, auth, fetchSettings, form, "revocation request failed", dpop)
	if err != nil {
		return err
	}

	// Per RFC 7009, any 2xx is success (even for already-revoked tokens).
	if resp.Status >= 200 && resp.Status < 300 {
		return nil
	}

	return parseErrorResponse(resp.Body, resp.Status)
}

func headersToMap(headers http.Header) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for name, values := range headers {
		if len(values) > 0 {
			out[name] = values[0]
		}
	}
	return out
}

// isUseDPoPNonceError checks whether an HTTP response body contains a use_dpop_nonce OAuth error.
func isUseDPoPNonceError(resp *ssrf.HTTPResponse) bool {
	if resp.Status < 400 {
		return false
	}
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &errResp); err != nil {
		return false
	}
	return errResp.Error == "use_dpop_nonce"
}

func postForm(ctx context.Context, endpoint string, auth ClientAuthentication, fetchSettings ssrf.FetchSettings, form url.Values, transportErrorPrefix string, dpop DPoPProvider) (*ssrf.HTTPResponse, error) {
	headers := http.Header{}
	if err := applyClientAuthentication(auth, form, headers); err != nil {
		return nil, err
	}

	extraHeaders := headersToMap(headers)

	// Attach DPoP proof headers if a provider is configured.
	if dpop != nil {
		dpopHeaders, err := dpop.BuildHeaders("POST", endpoint)
		if err != nil {
			return nil, err
		}
		if extraHeaders == nil {
			extraHeaders = make(map[string]string, len(dpopHeaders))
		}
		maps.Copy(extraHeaders, dpopHeaders)
	}

	resp, err := ssrf.SSRFSafePost(ctx, endpoint, fetchSettings, nil, ssrf.PostOptions{
		FormData:     form,
		ExtraHeaders: extraHeaders,
		MaxSize:      ssrf.MaxMetadataSize,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", transportErrorPrefix, err)
	}

	// Store server-issued DPoP nonce if present.
	if dpop != nil {
		if nonce := resp.Headers.Get("DPoP-Nonce"); nonce != "" {
			dpop.NoteNonce(endpoint, nonce)

			// Single retry only (no loop) per RFC 9449 §4.1.
			if isUseDPoPNonceError(resp) {
				dpopHeaders, err := dpop.BuildHeaders("POST", endpoint)
				if err != nil {
					return nil, err
				}
				retryExtra := headersToMap(headers)
				if retryExtra == nil {
					retryExtra = make(map[string]string, len(dpopHeaders))
				}
				maps.Copy(retryExtra, dpopHeaders)

				resp, err = ssrf.SSRFSafePost(ctx, endpoint, fetchSettings, nil, ssrf.PostOptions{
					FormData:     form,
					ExtraHeaders: retryExtra,
					MaxSize:      ssrf.MaxMetadataSize,
				})
				if err != nil {
					return nil, fmt.Errorf("%s: %w", transportErrorPrefix, err)
				}

				// Store nonce from retry response too.
				if retryNonce := resp.Headers.Get("DPoP-Nonce"); retryNonce != "" {
					dpop.NoteNonce(endpoint, retryNonce)
				}
			}
		}
	}

	return resp, nil
}

// doTokenRequest performs a token endpoint request and returns the response.
func doTokenRequest(ctx context.Context, endpoint string, auth ClientAuthentication, fetchSettings ssrf.FetchSettings, form url.Values, dpop DPoPProvider) (*TokenResponse, error) {
	resp, err := postForm(ctx, endpoint, auth, fetchSettings, form, "token request failed", dpop)
	if err != nil {
		return nil, err
	}

	if resp.Status < 200 || resp.Status >= 300 {
		return nil, parseErrorResponse(resp.Body, resp.Status)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(resp.Body, &tokenResp); err != nil {
		return nil, fmt.Errorf("token response: invalid JSON: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("%w: missing required field \"access_token\"", ErrProtocolError)
	}
	if tokenResp.TokenType == "" {
		return nil, fmt.Errorf("%w: missing required field \"token_type\"", ErrProtocolError)
	}

	// RFC 6749 §5.1: token_type is required and must be a type the SDK can use.
	// Our AS only issues Bearer and DPoP tokens.
	if !strings.EqualFold(tokenResp.TokenType, "Bearer") && !strings.EqualFold(tokenResp.TokenType, "DPoP") {
		return nil, fmt.Errorf("%w: unsupported token_type %q; only Bearer and DPoP are supported", ErrProtocolError, tokenResp.TokenType)
	}

	// RFC 9449 §5: when DPoP was used, token_type MUST be "DPoP".
	if dpop != nil && !strings.EqualFold(tokenResp.TokenType, "DPoP") {
		return nil, fmt.Errorf("%w: DPoP grant returned token_type %q, expected \"DPoP\"", ErrProtocolError, tokenResp.TokenType)
	}

	// RFC 6749 §5.1 ABNF: expires_in = 1*DIGIT — negative values are malformed.
	if tokenResp.ExpiresIn != nil && *tokenResp.ExpiresIn < 0 {
		return nil, fmt.Errorf("%w: expires_in must be non-negative, got %d", ErrProtocolError, *tokenResp.ExpiresIn)
	}

	NormalizeCnf(&tokenResp.Cnf, &tokenResp.CnfJkt)

	return &tokenResp, nil
}

// NormalizeCnf inspects the raw `cnf` JSON value: when it's a JSON object,
// derives the `cnf_jkt` thumbprint from `cnf.jkt`. When it's absent, null,
// or a non-object scalar, drops both fields so a malformed AS cannot
// pollute the typed confirmation-claim shape downstream.
//
// Exported so the package-external callers that build response structs
// from cached state (e.g. `core/authplane/client.go`'s
// `tokenResponseFromCache`) can apply the same derivation.
func NormalizeCnf(cnf *json.RawMessage, cnfJkt *string) {
	*cnfJkt = ""
	if len(*cnf) == 0 {
		return
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(*cnf, &obj); err != nil || obj == nil {
		// Non-object scalar or explicit `null` — drop both fields so a
		// malformed AS cannot pollute the typed shape downstream.
		*cnf = nil
		return
	}
	if jktRaw, ok := obj["jkt"]; ok {
		var jkt string
		if err := json.Unmarshal(jktRaw, &jkt); err == nil {
			*cnfJkt = jkt
		}
	}
}

// parseErrorResponse parses an OAuth 2.0 error response body.
func parseErrorResponse(body []byte, status int) error {
	var errResp struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		ConsentURL  string `json:"consent_url,omitempty"`
	}
	if err := json.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("HTTP %d: %s", status, string(body))
	}
	if errResp.Error != "" {
		if errResp.Error == "consent_required" || errResp.Error == "interaction_required" {
			return &ConsentRequiredError{
				ConsentURL:  errResp.ConsentURL,
				Description: errResp.Description,
				Cause:       mapOAuthError(errResp.Error),
			}
		}
		baseErr := mapOAuthError(errResp.Error)
		if errResp.Description != "" {
			return fmt.Errorf("%w: %s", baseErr, errResp.Description)
		}
		return baseErr
	}
	return fmt.Errorf("HTTP %d: %s", status, string(body))
}
