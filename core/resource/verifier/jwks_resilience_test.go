package verifier_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

func TestJWKS_UnknownKidDuringOutage_A20_A21(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	good, err := testutil.BuildJWKSWithKID(&key.PublicKey, "k1")
	if err != nil {
		t.Fatal(err)
	}
	var down atomic.Bool
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		DefaultTTL: time.Hour,
		FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
			if down.Load() {
				return nil, nil, errors.New("down")
			}
			return good, nil, nil
		},
	})
	t.Cleanup(jc.Close)
	ctx := context.Background()
	if err := jc.Prime(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := jc.GetKey(ctx, "other", jose.ES256); !errors.Is(err, verifier.ErrInvalidClaims) {
		t.Errorf("reachable: err = %v, want ErrInvalidClaims", err)
	}
	down.Store(true)
	// The forced window above is spent, so wait for it through a fresh cache instead.
	jc2 := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		DefaultTTL: time.Hour,
		FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
			if down.Load() {
				return nil, nil, errors.New("down")
			}
			return good, nil, nil
		},
	})
	t.Cleanup(jc2.Close)
	down.Store(false)
	if err := jc2.Prime(ctx); err != nil {
		t.Fatal(err)
	}
	down.Store(true)
	if _, err := jc2.GetKey(ctx, "other", jose.ES256); !errors.Is(err, verifier.ErrJWKSUnavailable) {
		t.Errorf("down: err = %v, want ErrJWKSUnavailable", err)
	}
	if _, err := jc2.GetKey(ctx, "k1", jose.ES256); err != nil {
		t.Errorf("known kid during outage: err = %v, want the cached key", err)
	}
}

func TestJWKS_BadDocumentsDoNotReplaceGoodKeys_A53(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	good, err := testutil.BuildJWKSWithKID(&key.PublicKey, "k1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for name, bad := range map[string]string{
		"empty object": `{}`,
		"empty set":    `{"keys":[]}`,
		"html":         `<html>maintenance</html>`,
	} {
		t.Run(name, func(t *testing.T) {
			var broken atomic.Bool
			jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
				DefaultTTL: time.Hour,
				FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
					if broken.Load() {
						return []byte(bad), nil, nil
					}
					return good, nil, nil
				},
			})
			t.Cleanup(jc.Close)
			if err := jc.Prime(ctx); err != nil {
				t.Fatal(err)
			}
			broken.Store(true)
			_, _ = jc.GetKey(ctx, "unknown", jose.ES256) // forces a refresh
			if _, err := jc.GetKey(ctx, "k1", jose.ES256); err != nil {
				t.Errorf("good key lost: %v", err)
			}
		})
	}
}

func TestJWKS_NonJWKSAtStartupFails_A53(t *testing.T) {
	for _, bad := range []string{`{}`, `<html>maintenance</html>`} {
		jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
			DefaultTTL: time.Hour,
			FetchFn:    func(context.Context) ([]byte, map[string][]string, error) { return []byte(bad), nil, nil },
		})
		t.Cleanup(jc.Close)
		if err := jc.Prime(context.Background()); !errors.Is(err, verifier.ErrJWKSUnavailable) {
			t.Errorf("Prime(%s): err = %v, want ErrJWKSUnavailable", bad, err)
		}
	}
}

func TestJWKS_UnsupportedKeyDoesNotDiscardOthers(t *testing.T) {
	doc := `{"keys":[{"kty":"unknown","kid":"x"},{"kty":"EC","crv":"P-256","kid":"k1","use":"sig",
	"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		DefaultTTL: time.Hour,
		FetchFn:    func(context.Context) ([]byte, map[string][]string, error) { return []byte(doc), nil, nil },
	})
	t.Cleanup(jc.Close)
	ctx := context.Background()
	if err := jc.Prime(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := jc.GetKey(ctx, "k1", jose.ES256); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestJWKS_MaxStale_A50_A51(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	good, err := testutil.BuildJWKSWithKID(&key.PublicKey, "k1")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name     string
		maxStale time.Duration
		wantErr  bool
	}{{"limit passed", time.Second, true}, {"no limit", 0, false}} {
		t.Run(tt.name, func(t *testing.T) {
			var down atomic.Bool
			jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
				DefaultTTL: time.Hour,
				MaxStale:   tt.maxStale,
				FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
					if down.Load() {
						return nil, nil, errors.New("down")
					}
					return good, nil, nil
				},
			})
			t.Cleanup(jc.Close)
			ctx := context.Background()
			if err := jc.Prime(ctx); err != nil {
				t.Fatal(err)
			}
			down.Store(true)
			time.Sleep(time.Second + 100*time.Millisecond)
			_, err := jc.GetKey(ctx, "k1", jose.ES256)
			if tt.wantErr && !errors.Is(err, verifier.ErrJWKSUnavailable) {
				t.Errorf("err = %v, want ErrJWKSUnavailable", err)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("err = %v, want the cached key", err)
			}
		})
	}
}

// The forced-refresh floor must not make a healthy endpoint read as stale.
func TestJWKS_MaxStaleHealthyEndpoint(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	good, err := testutil.BuildJWKSWithKID(&key.PublicKey, "k1")
	if err != nil {
		t.Fatal(err)
	}
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		DefaultTTL: time.Hour,
		MaxStale:   time.Second,
		FetchFn:    func(context.Context) ([]byte, map[string][]string, error) { return good, nil, nil },
	})
	t.Cleanup(jc.Close)
	ctx := context.Background()
	if err := jc.Prime(ctx); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		time.Sleep(time.Second + 100*time.Millisecond)
		if _, err := jc.GetKey(ctx, "k1", jose.ES256); err != nil {
			t.Fatalf("healthy endpoint: %v", err)
		}
	}
}

// Requests past the age limit must not drive one fetch each: the check runs before any
// signature is verified.
func TestJWKS_MaxStaleFloorLimitsFetches_A50(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	good, err := testutil.BuildJWKSWithKID(&key.PublicKey, "k1")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var slow atomic.Bool
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		DefaultTTL: time.Hour,
		MaxStale:   time.Second,
		FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
			calls.Add(1)
			if slow.Load() {
				time.Sleep(50 * time.Millisecond)
			}
			return good, nil, nil
		},
	})
	t.Cleanup(jc.Close)
	ctx := context.Background()
	if err := jc.Prime(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second + 100*time.Millisecond)
	slow.Store(true)
	before := calls.Load()
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = jc.GetKey(ctx, "k1", jose.ES256)
		}()
	}
	wg.Wait()
	if got := calls.Load() - before; got != 1 {
		t.Errorf("fetches = %d, want 1", got)
	}
}

// A document fetched earlier can never overwrite one fetched later, so a removed key
// cannot come back through a caller finishing late.
func TestJWKS_RemovedKeyStaysRemoved_A53(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	withKey, err := testutil.BuildJWKSWithKID(&key.PublicKey, "old")
	if err != nil {
		t.Fatal(err)
	}
	other, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	without, err := testutil.BuildJWKSWithKID(&other.PublicKey, "new")
	if err != nil {
		t.Fatal(err)
	}
	var removed atomic.Bool
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		DefaultTTL: 50 * time.Millisecond,
		FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
			if removed.Load() {
				return without, nil, nil
			}
			return withKey, nil, nil
		},
	})
	t.Cleanup(jc.Close)
	ctx := context.Background()
	if err := jc.Prime(ctx); err != nil {
		t.Fatal(err)
	}
	removed.Store(true)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = jc.GetKey(ctx, "unknown", jose.ES256)
		}()
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	if _, err := jc.GetKey(ctx, "old", jose.ES256); err == nil {
		t.Error("the removed key is trusted again")
	}
}

// A caller whose context ended gets that error rather than a report of an outage.
func TestJWKS_DepartedCallerGetsContextError_A85(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		DefaultTTL: time.Hour,
		FetchFn:    func(context.Context) ([]byte, map[string][]string, error) { return []byte(`{"keys":[]}`), nil, nil },
	})
	t.Cleanup(jc.Close)
	if err := jc.Prime(context.Background()); err != nil {
		t.Fatal(err)
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := jc.GetKey(gone, "k", jose.ES256)
	if !errors.Is(err, context.Canceled) || errors.Is(err, verifier.ErrJWKSUnavailable) {
		t.Errorf("err = %v", err)
	}
}

// With a maximum age, a caller leaving while the refresh runs is still not an outage.
func TestJWKS_DepartedCallerWithMaxStale_A85(t *testing.T) {
	release := make(chan struct{})
	var first sync.Once
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		DefaultTTL: time.Hour,
		MaxStale:   time.Second,
		FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
			ok := false
			first.Do(func() { ok = true })
			if !ok {
				<-release
				return nil, nil, errors.New("down")
			}
			return []byte(`{"keys":[]}`), nil, nil
		},
	})
	t.Cleanup(jc.Close)
	t.Cleanup(func() { close(release) })
	if err := jc.Prime(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := jc.GetKey(ctx, "k", jose.ES256)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, verifier.ErrJWKSUnavailable) {
		t.Errorf("err = %v, want the context error", err)
	}
}
