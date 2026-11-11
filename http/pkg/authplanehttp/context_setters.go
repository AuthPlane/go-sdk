package authplanehttp

import (
	"context"

	"github.com/authplane/go-sdk/core/resource/verifier"
)

// ContextWithClaims returns a context carrying the given VerifiedClaims under
// the same context key Middleware uses, so ClaimsFromContext can retrieve them
// downstream. Production handlers should rely on Middleware to populate this;
// these setters exist for tests and for callers that manage the bearer/DPoP
// flow outside Middleware.
func ContextWithClaims(ctx context.Context, claims *verifier.VerifiedClaims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// ContextWithToken returns a context carrying the given raw bearer token under
// the same context key Middleware uses. See ContextWithClaims for usage notes.
func ContextWithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey{}, token)
}
