package authplane_test

import (
	"context"
	"fmt"
	"log"

	"github.com/authplane/go-sdk/core/authplane"
)

func ExampleNewClient() {
	ctx := context.Background()
	client, err := authplane.NewClient(ctx, "https://auth.example.com",
		authplane.WithClientCredentials("client-id", "client-secret"))
	if err != nil {
		fmt.Println("start the authorization server first")
		return
	}
	defer func() { _ = client.Close() }()

	token, err := client.ClientCredentials(ctx, authplane.ClientCredentialsInput{Scopes: []string{"read"}})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token.TokenType)
}
