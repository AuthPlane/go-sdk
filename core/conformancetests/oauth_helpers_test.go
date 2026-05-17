package conformancetests

import (
	"context"

	"github.com/authplane/go-sdk/core/internal/oauth"
	"github.com/authplane/go-sdk/core/internal/ssrf"
)

func testOAuthAuth(clientID, clientSecret string) oauth.ClientAuthentication {
	return oauth.ClientAuthentication{
		Method:       oauth.ClientAuthClientSecretBasic,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

func testOAuthFetchSettings() ssrf.FetchSettings {
	return ssrf.DevModeFetchSettings()
}

func testClientCredentials(ctx context.Context, endpoint, clientID, clientSecret string, scopes []string, resources []string) (*oauth.TokenResponse, error) {
	return oauth.ClientCredentials(ctx, endpoint, testOAuthAuth(clientID, clientSecret), testOAuthFetchSettings(), scopes, resources, nil)
}

func testTokenExchange(ctx context.Context, endpoint, clientID, clientSecret string, in oauth.TokenExchangeInput) (*oauth.TokenResponse, error) {
	return oauth.TokenExchange(ctx, endpoint, testOAuthAuth(clientID, clientSecret), testOAuthFetchSettings(), in, nil)
}

func testIntrospect(ctx context.Context, endpoint, clientID, clientSecret, token string) (*oauth.IntrospectionResponse, error) {
	return oauth.Introspect(ctx, endpoint, testOAuthAuth(clientID, clientSecret), testOAuthFetchSettings(), token, nil)
}

func testRevoke(ctx context.Context, endpoint, clientID, clientSecret, token string) error {
	return oauth.Revoke(ctx, endpoint, testOAuthAuth(clientID, clientSecret), testOAuthFetchSettings(), token, nil)
}
