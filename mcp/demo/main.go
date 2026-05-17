// Calculator Service — Authplane MCP Go adapter demo.
//
// Demonstrates:
//   - Token introspection for revocation checking (RFC 7662)
//   - Per-tool scope enforcement via ClaimsFromContext
//
// Setup:
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
	"github.com/authplane/go-sdk/mcp/pkg/authplanemcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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

	adapter, err := authplanemcp.NewAdapter(ctx, authplanemcp.Options{
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

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "Calculator Service",
		Version: "0.1.0",
	}, nil)

	// add — requires scope "tools/add"
	type AddArgs struct {
		A float64 `json:"a"`
		B float64 `json:"b"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "add",
		Description: "Add two numbers",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args AddArgs) (*mcp.CallToolResult, any, error) {
		claims := authplanemcp.ClaimsFromContext(ctx)
		if claims == nil {
			return nil, nil, verifier.ErrTokenMissing
		}
		if err := claims.RequireScope("tools/add"); err != nil {
			return nil, nil, err
		}
		return textResult(fmt.Sprintf("%g", args.A+args.B)), nil, nil
	})

	// multiply — requires scope "tools/multiply"
	type MultiplyArgs struct {
		A float64 `json:"a"`
		B float64 `json:"b"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "multiply",
		Description: "Multiply two numbers",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args MultiplyArgs) (*mcp.CallToolResult, any, error) {
		claims := authplanemcp.ClaimsFromContext(ctx)
		if claims == nil {
			return nil, nil, verifier.ErrTokenMissing
		}
		if err := claims.RequireScope("tools/multiply"); err != nil {
			return nil, nil, err
		}
		return textResult(fmt.Sprintf("%g", args.A*args.B)), nil, nil
	})

	handler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return server
	}, nil)

	http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
	http.Handle("/mcp", adapter.AuthMiddleware(handler))

	slog.Info("Calculator MCP server listening", "url", "http://localhost:"+port)

	return http.ListenAndServe(":"+port, nil)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}
