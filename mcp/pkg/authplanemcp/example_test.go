package authplanemcp_test

import (
	"context"
	"log"
	"net/http"

	"github.com/authplane/go-sdk/mcp/pkg/authplanemcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func ExampleNewAdapter() {
	adapter, err := authplanemcp.NewAdapter(context.Background(), authplanemcp.Options{
		Issuer:   "https://auth.example.com",
		Resource: "https://mcp.example.com/mcp",
		Scopes:   []string{"tools/ping"},
	})
	if err != nil {
		return
	}
	defer func() { _ = adapter.Close() }()

	server := mcp.NewServer(&mcp.Implementation{Name: "Ping", Version: "0.1.0"}, nil)
	server.AddReceivingMiddleware(adapter.ReceivingMiddleware())
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true})

	mux := http.NewServeMux()
	mux.Handle(adapter.WellKnownPRMPath(), adapter.PRMHandler())
	mux.Handle("/mcp", adapter.AuthMiddleware(handler))
	log.Fatal(http.ListenAndServe(":8080", mux)) //nolint:gosec // an example
}
