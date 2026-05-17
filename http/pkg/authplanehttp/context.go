package authplanehttp

import (
	"context"

	"github.com/authplane/go-sdk/core/resource/verifier"
)

// claimsKey is the context key used to store VerifiedClaims for downstream handlers.
type claimsKey struct{}

// tokenKey is the context key used to store the raw bearer token for downstream handlers.
type tokenKey struct{}

// ClaimsFromContext returns the VerifiedClaims injected by Middleware into
// the request context. Returns nil if called outside an authenticated request.
func ClaimsFromContext(ctx context.Context) *verifier.VerifiedClaims {
	claims, _ := ctx.Value(claimsKey{}).(*verifier.VerifiedClaims)
	return claims
}

// TokenFromContext returns the raw bearer token injected by Middleware into
// the request context. Returns an empty string if called outside an authenticated request.
func TokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(tokenKey{}).(string)
	return token
}
