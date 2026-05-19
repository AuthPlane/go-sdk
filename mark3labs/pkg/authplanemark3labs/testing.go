package authplanemark3labs

import (
	"context"

	"github.com/authplane/go-sdk/core/resource/verifier"
)

// ContextWithClaims returns a context carrying the given VerifiedClaims,
// as if AuthMiddleware had validated a request. Use in tests only.
func ContextWithClaims(ctx context.Context, claims *verifier.VerifiedClaims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// ContextWithToken returns a context carrying the given raw bearer token,
// as if AuthMiddleware had injected it. Use in tests only.
func ContextWithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey{}, token)
}
