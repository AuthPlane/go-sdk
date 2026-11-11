package authplane

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
)

// Setup describes a client and the one resource it protects, as the MCP adapters build them.
type Setup struct {
	Issuer              string
	Resource            string
	Scopes              []string
	ResourceMetadataURL string
	// DevMode applies DevModeFetchSettings before ClientOptions, which can override it.
	DevMode         bool
	ClientOptions   []Option
	VerifierOptions []verifier.Option
}

// NewClientAndResource builds both. If the resource cannot be built, the client is closed.
func NewClientAndResource(ctx context.Context, setup Setup) (*Client, *resource.Resource, error) {
	clientOpts := make([]Option, 0, 1+len(setup.ClientOptions))
	if setup.DevMode {
		clientOpts = append(clientOpts, WithFetchSettings(DevModeFetchSettings()))
	}
	clientOpts = append(clientOpts, setup.ClientOptions...)
	client, err := NewClient(ctx, setup.Issuer, clientOpts...)
	if err != nil {
		return nil, nil, err
	}
	resourceOpts := []resource.Option{resource.WithScopes(setup.Scopes...)}
	if setup.ResourceMetadataURL != "" {
		resourceOpts = append(resourceOpts, resource.WithResourceMetadataURL(setup.ResourceMetadataURL))
	}
	if len(setup.VerifierOptions) > 0 {
		resourceOpts = append(resourceOpts, resource.WithVerifierOptions(setup.VerifierOptions...))
	}
	res, err := client.Resource(setup.Resource, resourceOpts...)
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	return client, res, nil
}

// NewElicitationID returns a random v4 UUID for an MCP elicitation.
func NewElicitationID() string {
	var u [16]byte
	_, _ = rand.Read(u[:])      // crypto/rand.Read never returns an error on supported platforms
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:])
}
