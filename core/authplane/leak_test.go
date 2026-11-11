package authplane_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
)

// A closed client must leave no background goroutine behind.
func TestClient_CloseLeavesNoGoroutines_A93(t *testing.T) {
	server, serverURL := mockAS(t)
	runtime.GC()
	before := runtime.NumGoroutine()
	for range 20 {
		client, err := authplane.NewClient(context.Background(), serverURL,
			authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Pooled connections end with the server; a client's own goroutines must end with Close.
	server.Close()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+2 {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines = %d, started with %d", runtime.NumGoroutine(), before)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
