package authplanemark3labs

import (
	"context"

	"github.com/authplane/go-sdk/core/resource/verifier"
	authplanehttp "github.com/authplane/go-sdk/http/pkg/authplanehttp"
)

// ContextWithClaims returns a context carrying the given VerifiedClaims under
// the same context key AuthMiddleware uses, so ClaimsFromContext (and the
// per-tool-call context bridged by HTTPContextFunc) can retrieve them
// downstream. Production handlers should rely on AuthMiddleware to populate
// this; these setters exist for tests and for callers that manage the
// bearer/DPoP flow outside AuthMiddleware.
//
// Thin wrapper around authplanehttp.ContextWithClaims so the mark3labs and
// http adapters share a single context-key namespace.
func ContextWithClaims(ctx context.Context, claims *verifier.VerifiedClaims) context.Context {
	return authplanehttp.ContextWithClaims(ctx, claims)
}

// ContextWithToken returns a context carrying the given raw bearer token under
// the same context key AuthMiddleware uses. See ContextWithClaims for usage
// notes.
//
// Thin wrapper around authplanehttp.ContextWithToken for the same reason as
// ContextWithClaims.
func ContextWithToken(ctx context.Context, token string) context.Context {
	return authplanehttp.ContextWithToken(ctx, token)
}
