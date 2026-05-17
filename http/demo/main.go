// Calculator Service — Authplane HTTP adapter demo.
//
// Demonstrates:
//   - Token introspection for revocation checking (RFC 7662)
//   - Per-route scope enforcement via RequireScopes middleware
//
// Setup:
//
//	go run ./demo/
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/http/pkg/authplanehttp"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	issuer := env("ISSUER_URL", "http://localhost:9000")
	resourceURL := env("RESOURCE_URL", "http://localhost:8080/mcp")
	clientID := env("CLIENT_ID", resourceURL)
	clientSecret := env("CLIENT_SECRET", "")
	port := env("PORT", "8080")

	ctx := context.Background()

	// WithClientCredentials wires introspection (revocation) and enables token exchange.
	var clientOpts []authplane.Option
	if clientSecret != "" {
		clientOpts = append(clientOpts, authplane.WithClientCredentials(clientID, clientSecret))
	}
	clientOpts = append(clientOpts, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))

	client, err := authplane.NewClient(ctx, issuer, clientOpts...)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer func() { _ = client.Close() }()

	res, err := client.Resource(resourceURL,
		resource.WithScopes("tools/add", "tools/multiply"),
	)
	if err != nil {
		return fmt.Errorf("create resource: %w", err)
	}

	adapter := authplanehttp.New(res)

	mux := http.NewServeMux()
	mux.Handle(adapter.WellKnownPRMPath(), adapter.PRMHandler())
	mux.Handle("/mcp/add", adapter.RequireScopes("tools/add")(http.HandlerFunc(addHandler)))
	mux.Handle("/mcp/multiply", adapter.RequireScopes("tools/multiply")(http.HandlerFunc(multiplyHandler)))

	slog.Info("Calculator HTTP server listening", "url", "http://localhost:"+port)

	return http.ListenAndServe(":"+port, adapter.Middleware()(mux))
}

type mathRequest struct {
	A float64 `json:"a"`
	B float64 `json:"b"`
}

type mathResponse struct {
	Result float64 `json:"result"`
}

func addHandler(w http.ResponseWriter, r *http.Request) {
	var req mathRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	writeJSON(w, mathResponse{Result: req.A + req.B})
}

func multiplyHandler(w http.ResponseWriter, r *http.Request) {
	var req mathRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	writeJSON(w, mathResponse{Result: req.A * req.B})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
