package authplanemark3labs_test

import (
	"context"
	"log"
	"net/http"

	"github.com/authplane/go-sdk/mark3labs/pkg/authplanemark3labs"
	"github.com/mark3labs/mcp-go/server"
)

func ExampleNewAdapter() {
	adapter, err := authplanemark3labs.NewAdapter(context.Background(), authplanemark3labs.Options{
		Issuer:   "https://auth.example.com",
		Resource: "https://mcp.example.com/mcp",
		Scopes:   []string{"tools/ping"},
	})
	if err != nil {
		return
	}
	defer func() { _ = adapter.Close() }()

	mcpServer := server.NewMCPServer("Ping", "0.1.0", server.WithToolCapabilities(false))
	streamable := server.NewStreamableHTTPServer(mcpServer,
		server.WithHTTPContextFunc(adapter.HTTPContextFunc()),
		server.WithSessionIdManagerResolver(adapter.SessionManager()))

	mux := http.NewServeMux()
	mux.Handle(adapter.WellKnownPRMPath(), adapter.PRMHandler())
	mux.Handle("/mcp", adapter.AuthMiddleware(streamable))
	log.Fatal(http.ListenAndServe(":8080", mux)) //nolint:gosec // an example
}
