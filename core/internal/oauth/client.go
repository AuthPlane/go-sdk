// Package oauth implements OAuth 2.0 client operations (token exchange, introspection, revocation).
package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/authplane/go-sdk/core/internal/ssrf"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

// TokenTypeNotApplicable is the token_type of a token exchange result that is not an
// access token (RFC 8693 section 2.2.1).
const TokenTypeNotApplicable = "N_A"

// ValidateClientAuthentication validates client-credentials style auth settings.
func ValidateClientAuthentication(auth ClientAuthentication) error {
	auth.ClientID = strings.TrimSpace(auth.ClientID)
	auth.ClientSecret = strings.TrimSpace(auth.ClientSecret)
	if auth.ClientID == "" {
		return fmt.Errorf("%w: client_id must not be empty", ErrInvalidRequest)
	}
	switch auth.Method {
	case ClientAuthClientSecretBasic, ClientAuthClientSecretPost:
		if auth.ClientSecret == "" {
			return fmt.Errorf("%w: client_secret must not be empty", ErrInvalidRequest)
		}
		return nil
	case ClientAuthPrivateKeyJWT:
		if auth.SigningKey == nil {
			return fmt.Errorf("%w: private_key_jwt needs a signing key", ErrInvalidRequest)
		}
		switch auth.SigningAlg {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
			jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
			return nil
		}
		return fmt.Errorf("%w: private_key_jwt needs an asymmetric algorithm, got %q", ErrInvalidRequest, auth.SigningAlg)
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

func applyClientAuthentication(auth ClientAuthentication, form url.Values, headers http.Header, endpoint string, isTokenEndpoint bool) error {
	if err := ValidateClientAuthentication(auth); err != nil {
		return err
	}
	switch auth.Method {
	case ClientAuthClientSecretBasic:
		headers.Set("Authorization", basicAuth(auth))
	case ClientAuthClientSecretPost:
		form.Set("client_id", auth.ClientID)
		form.Set("client_secret", auth.ClientSecret)
	case ClientAuthPrivateKeyJWT:
		audience := auth.issuer
		if auth.AssertionAudienceTokenEndpoint && isTokenEndpoint {
			audience = endpoint
		}
		if audience == "" {
			return fmt.Errorf("%w: private_key_jwt needs an issuer for the assertion audience", ErrInvalidRequest)
		}
		assertion, err := signClientAssertion(auth, audience)
		if err != nil {
			return err
		}
		form.Set("client_id", auth.ClientID)
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	default:
		return fmt.Errorf("%w: unsupported client auth method %q", ErrInvalidRequest, auth.Method)
	}
	return nil
}

const (
	clientAssertionType     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	clientAssertionTyp      = "client-authentication+jwt"
	clientAssertionLifetime = 60 * time.Second
)

// signClientAssertion builds an RFC 7523 section 2.2 assertion. Each call has a fresh
// jti, so a retried request never replays one.
func signClientAssertion(auth ClientAuthentication, audience string) (string, error) {
	opts := (&jose.SignerOptions{}).WithType(clientAssertionTyp)
	if auth.KeyID != "" {
		opts = opts.WithHeader("kid", auth.KeyID)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: auth.SigningAlg, Key: cryptosigner.Opaque(auth.SigningKey)}, opts)
	if err != nil {
		return "", fmt.Errorf("%w: client assertion signer: %v", ErrInvalidRequest, err)
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("client assertion jti: %w", err)
	}
	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"iss": auth.ClientID,
		"sub": auth.ClientID,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(clientAssertionLifetime).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(jti),
	})
	if err != nil {
		return "", fmt.Errorf("client assertion: %w", err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("client assertion: %w", err)
	}
	return signed.CompactSerialize()
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
	return strings.Join(NormalizeRequestValues(scopes), " ")
}

// ClientCredentials performs a client_credentials grant.
func ClientCredentials(ctx context.Context, endpoint string, auth ClientAuthentication, fetchSettings ssrf.FetchSettings, scopes, resources []string, dpop DPoPProvider) (*TokenResponse, error) {
	return ClientCredentialsWithDetails(ctx, endpoint, auth, fetchSettings, scopes, resources, nil, dpop)
}

// ClientCredentialsWithDetails is ClientCredentials with RFC 9396 authorization_details.
func ClientCredentialsWithDetails(ctx context.Context, endpoint string, auth ClientAuthentication, fetchSettings ssrf.FetchSettings, scopes, resources []string, details json.RawMessage, dpop DPoPProvider) (*TokenResponse, error) {
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
	if err := setAuthorizationDetails(form, details); err != nil {
		return nil, err
	}

	return doTokenRequest(ctx, endpoint, auth, fetchSettings, form, dpop, false)
}

// JWTBearer performs an RFC 7523 section 2.1 JWT-bearer grant.
func JWTBearer(ctx context.Context, endpoint string, auth ClientAuthentication, fetchSettings ssrf.FetchSettings, in JWTBearerInput, dpop DPoPProvider) (*TokenResponse, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("%w: token endpoint not configured", ErrInvalidRequest)
	}
	assertion := strings.TrimSpace(in.Assertion)
	if assertion == "" {
		return nil, fmt.Errorf("%w: assertion must not be empty", ErrInvalidRequest)
	}

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	if scope := normalizedScopeString(in.Scopes); scope != "" {
		form.Set("scope", scope)
	}
	for _, resource := range NormalizeRequestValues(in.Resources) {
		form.Add("resource", resource)
	}
	if err := setAuthorizationDetails(form, in.AuthorizationDetails); err != nil {
		return nil, err
	}

	return doTokenRequest(ctx, endpoint, auth, fetchSettings, form, dpop, false)
}

// setAuthorizationDetails adds RFC 9396 authorization_details, which must be a JSON array.
func setAuthorizationDetails(form url.Values, details json.RawMessage) error {
	if len(details) == 0 {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(details, &items); err != nil {
		return fmt.Errorf("%w: authorization_details must be a JSON array", ErrInvalidRequest)
	}
	form.Set("authorization_details", string(details))
	return nil
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
	if err := setAuthorizationDetails(form, in.AuthorizationDetails); err != nil {
		return nil, err
	}

	resp, err := doTokenRequest(ctx, endpoint, auth, fetchSettings, form, dpop, true)
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
		return nil, ErrNoIntrospectionEndpoint
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("%w: token must not be empty", ErrInvalidRequest)
	}

	form := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}

	resp, err := postForm(ctx, endpoint, false, auth, fetchSettings, form, "introspection request failed", dpop)
	if err != nil {
		return nil, err
	}

	if resp.Status < 200 || resp.Status >= 300 {
		return nil, parseErrorResponse(resp)
	}

	// active is read alone first, and only a single exact "active": true is active. Anything
	// else is final as inactive, whatever other fields hold: one badly typed field must not
	// become a parse error that fail-open accepts, and Go's decoder would otherwise read a
	// case-variant or duplicate key as active.
	active, err := readActive(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("introspection: invalid JSON response: %w", err)
	}
	if !active {
		return &IntrospectionResponse{}, nil
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

	resp, err := postForm(ctx, endpoint, false, auth, fetchSettings, form, "revocation request failed", dpop)
	if err != nil {
		return err
	}

	// Per RFC 7009, any 2xx is success (even for already-revoked tokens).
	if resp.Status >= 200 && resp.Status < 300 {
		return nil
	}

	return parseErrorResponse(resp)
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

func postForm(ctx context.Context, endpoint string, isTokenEndpoint bool, auth ClientAuthentication, fetchSettings ssrf.FetchSettings, form url.Values, transportErrorPrefix string, dpop DPoPProvider) (*ssrf.HTTPResponse, error) {
	// send authenticates each attempt separately, so a retry gets a fresh assertion.
	send := func() (*ssrf.HTTPResponse, error) {
		attempt := maps.Clone(form)
		headers := http.Header{}
		if err := applyClientAuthentication(auth, attempt, headers, endpoint, isTokenEndpoint); err != nil {
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
		resp, err := ssrf.SSRFSafePost(ctx, endpoint, fetchSettings, ssrf.PostOptions{
			FormData:     attempt,
			ExtraHeaders: extraHeaders,
			MaxSize:      ssrf.MaxMetadataSize,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", transportErrorPrefix, err)
		}
		return resp, nil
	}

	resp, err := send()
	if err != nil {
		return nil, err
	}

	// Store server-issued DPoP nonce if present.
	if dpop != nil {
		if nonce := resp.Headers.Get("DPoP-Nonce"); nonce != "" {
			dpop.NoteNonce(endpoint, nonce)

			// Single retry only (no loop) per RFC 9449 §4.1.
			if isUseDPoPNonceError(resp) {
				resp, err = send()
				if err != nil {
					return nil, err
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
//
// allowNotApplicable accepts token_type N_A, which RFC 8693 section 2.2.1 defines for a
// token exchange that issues something other than an access token.
func doTokenRequest(ctx context.Context, endpoint string, auth ClientAuthentication, fetchSettings ssrf.FetchSettings, form url.Values, dpop DPoPProvider, allowNotApplicable bool) (*TokenResponse, error) {
	resp, err := postForm(ctx, endpoint, true, auth, fetchSettings, form, "token request failed", dpop)
	if err != nil {
		return nil, err
	}

	if resp.Status < 200 || resp.Status >= 300 {
		return nil, parseErrorResponse(resp)
	}

	tokenResp, err := decodeTokenResponse(resp.Body)
	if err != nil {
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
	notApplicable := allowNotApplicable && strings.EqualFold(tokenResp.TokenType, TokenTypeNotApplicable)
	if !notApplicable && !strings.EqualFold(tokenResp.TokenType, "Bearer") && !strings.EqualFold(tokenResp.TokenType, "DPoP") {
		return nil, fmt.Errorf("%w: unsupported token_type %q; only Bearer and DPoP are supported", ErrProtocolError, tokenResp.TokenType)
	}

	// RFC 9449 §5: when DPoP was used, token_type MUST be "DPoP".
	if dpop != nil && !notApplicable && !strings.EqualFold(tokenResp.TokenType, "DPoP") {
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

// readActive reports whether an introspection answer's object has exactly one member named
// "active", holding true. It returns an error only for a body that is not valid JSON.
func readActive(body []byte) (bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	if token != json.Delim('{') {
		// A well-formed answer that is not an object says nothing is active.
		if json.Valid(body) {
			return false, nil
		}
		return false, errors.New("not valid JSON")
	}
	active, members := false, 0
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return false, err
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false, err
		}
		name, _ := key.(string)
		if strings.EqualFold(name, "active") {
			members++
			active = name == "active" && string(bytes.TrimSpace(value)) == "true"
		}
	}
	if _, err := decoder.Token(); err != nil {
		return false, err
	}
	return active && members == 1, nil
}

// decodeTokenResponse decodes a token response, tolerating expires_in sent as a string.
func decodeTokenResponse(body []byte) (TokenResponse, error) {
	type plain TokenResponse
	var decoded struct {
		plain
		ExpiresIn *flexibleInt64 `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return TokenResponse{}, err
	}
	result := TokenResponse(decoded.plain)
	if decoded.ExpiresIn != nil {
		value := int64(*decoded.ExpiresIn)
		result.ExpiresIn = &value
	}
	return result, nil
}

// maxServerTextLen bounds the server-controlled text kept from an error answer, since errors
// reach logs.
const maxServerTextLen = 256

// cleanServerText makes server-controlled text safe for an error message: printable, on one
// line, and short.
func cleanServerText(text []byte) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, strings.ToValidUTF8(string(text), " "))
	cleaned = strings.TrimSpace(cleaned)
	if len(cleaned) > maxServerTextLen {
		cleaned = strings.ToValidUTF8(cleaned[:maxServerTextLen], "") + "..."
	}
	return cleaned
}

// parseErrorResponse parses an OAuth 2.0 error answer.
func parseErrorResponse(resp *ssrf.HTTPResponse) error {
	oauthErr := &ResponseError{Status: resp.Status}
	if seconds, err := strconv.Atoi(strings.TrimSpace(resp.Headers.Get("Retry-After"))); err == nil && seconds > 0 {
		oauthErr.RetryAfter = time.Duration(seconds) * time.Second
	}
	var errResp struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		ConsentURL  string `json:"consent_url,omitempty"`
	}
	if err := json.Unmarshal(resp.Body, &errResp); err != nil || errResp.Error == "" {
		oauthErr.Description = cleanServerText(resp.Body)
		return oauthErr
	}
	oauthErr.Code = errResp.Error
	oauthErr.Description = cleanServerText([]byte(errResp.Description))
	oauthErr.cause = mapOAuthError(errResp.Error)
	if errResp.Error == "consent_required" || errResp.Error == "interaction_required" {
		return &ConsentRequiredError{
			ConsentURL:  errResp.ConsentURL,
			Description: oauthErr.Description,
			Cause:       oauthErr,
		}
	}
	return oauthErr
}
