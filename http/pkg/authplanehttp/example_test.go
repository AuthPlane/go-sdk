package authplanehttp_test

import (
	"context"
	"log"
	"net/http"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/http/pkg/authplanehttp"
)

func ExampleNew() {
	ctx := context.Background()
	client, err := authplane.NewClient(ctx, "https://auth.example.com")
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()
	res, err := client.Resource("https://api.example.com/mcp")
	if err != nil {
		log.Fatal(err)
	}
	adapter, err := authplanehttp.New(res)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(adapter.WellKnownPRMPath(), adapter.PRMHandler())
	mux.Handle("/mcp", adapter.RequireScopes("read")(http.NotFoundHandler()))
	_ = http.ListenAndServe(":8080", adapter.Middleware()(mux)) //nolint:gosec // an example
}
