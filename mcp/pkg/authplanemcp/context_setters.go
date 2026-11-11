package authplanemcp

import (
	"context"

	"github.com/authplane/go-sdk/core/resource/verifier"
)

// ContextWithClaims returns a context carrying the given VerifiedClaims,
// as if AuthMiddleware had validated a request. Use in tests only.
func ContextWithClaims(ctx context.Context, claims *verifier.VerifiedClaims) context.Context {
	holder := &claimsHolder{claims: claims}
	if existing := currentHolder(ctx); existing != nil {
		holder.token = existing.token
	}
	return context.WithValue(ctx, claimsKey{}, holder)
}

// ContextWithToken returns a context carrying the given raw bearer token,
// as if AuthMiddleware had injected it. Use in tests only.
func ContextWithToken(ctx context.Context, token string) context.Context {
	holder := &claimsHolder{token: token}
	if existing := currentHolder(ctx); existing != nil {
		holder.claims = existing.claims
	}
	return context.WithValue(ctx, claimsKey{}, holder)
}
