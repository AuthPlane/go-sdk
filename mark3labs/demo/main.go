// Calculator Service — Authplane mark3labs/mcp-go adapter demo.
//
// Mirrors the official-SDK demo at go-sdk/mcp/demo/, demonstrating:
//   - Token introspection for revocation checking (RFC 7662)
//   - Per-tool scope enforcement via ClaimsFromContext
//   - Bridging verified claims from AuthMiddleware into the per-tool-call
//     MCP context via server.WithHTTPContextFunc(adapter.HTTPContextFunc())
//
// Run:
//
//	go run ./demo/
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/mark3labs/pkg/authplanemark3labs"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	issuer := env("ISSUER_URL", "http://localhost:9000")
	resource := env("RESOURCE_URL", "http://localhost:8080/mcp")
	clientID := env("CLIENT_ID", resource)
	clientSecret := env("CLIENT_SECRET", "")
	port := env("PORT", "8080")

	ctx := context.Background()

	// WithClientCredentials wires introspection (revocation) and enables token exchange.
	var clientOpts []authplane.Option
	if clientSecret != "" {
		clientOpts = append(clientOpts, authplane.WithClientCredentials(clientID, clientSecret))
	}

	adapter, err := authplanemark3labs.NewAdapter(ctx, authplanemark3labs.Options{
		Issuer:        issuer,
		Resource:      resource,
		Scopes:        []string{"tools/add", "tools/multiply"},
		DevMode:       true, // relaxes SSRF for local dev; remove before deploying to production
		ClientOptions: clientOpts,
	})
	if err != nil {
		return fmt.Errorf("initialize adapter: %w", err)
	}
	defer func() { _ = adapter.Close() }()

	mcpServer := server.NewMCPServer(
		"Calculator Service",
		"0.1.0",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	// add — requires scope "tools/add"
	addTool := mcp.NewTool("add",
		mcp.WithDescription("Add two numbers"),
		mcp.WithNumber("a", mcp.Required(), mcp.Description("First addend")),
		mcp.WithNumber("b", mcp.Required(), mcp.Description("Second addend")),
	)
	mcpServer.AddTool(addTool, scopedHandler("tools/add", func(a, b float64) float64 {
		return a + b
	}))

	// multiply — requires scope "tools/multiply"
	multiplyTool := mcp.NewTool("multiply",
		mcp.WithDescription("Multiply two numbers"),
		mcp.WithNumber("a", mcp.Required(), mcp.Description("First factor")),
		mcp.WithNumber("b", mcp.Required(), mcp.Description("Second factor")),
	)
	mcpServer.AddTool(multiplyTool, scopedHandler("tools/multiply", func(a, b float64) float64 {
		return a * b
	}))

	// Wire HTTPContextFunc so AuthMiddleware's per-request claims/token reach
	// each tool handler's context.
	streamable := server.NewStreamableHTTPServer(mcpServer,
		server.WithHTTPContextFunc(adapter.HTTPContextFunc()),
	)

	http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
	http.Handle("/mcp", adapter.AuthMiddleware(streamable))

	slog.Info("Calculator MCP server listening", "url", "http://localhost:"+port)

	return http.ListenAndServe(":"+port, nil)
}

// scopedHandler returns a mark3labs/mcp-go tool handler that first enforces
// the required OAuth scope via ClaimsFromContext, then performs the operation.
//
// Scope failure is surfaced as a CallToolResult with IsError=true rather than
// a returned error: mark3labs/mcp-go coerces handler-returned errors to
// JSON-RPC -32603 (INTERNAL_ERROR), so an isError result is the only way to
// give the client a structured failure with details.
func scopedHandler(scope string, op func(a, b float64) float64) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		claims := authplanemark3labs.ClaimsFromContext(ctx)
		if claims == nil {
			return mcp.NewToolResultError(verifier.ErrTokenMissing.Error()), nil
		}
		if err := claims.RequireScope(scope); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		a, err := request.RequireFloat("a")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		b, err := request.RequireFloat("b")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("%g", op(a, b))), nil
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
