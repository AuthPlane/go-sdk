package authplanemcp_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/mcp/pkg/authplanemcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`

type rpcResponse struct {
	StatusCode int
	Header     http.Header
}

func rpc(t *testing.T, url, token, session, body string, headers map[string]string) (rpcResponse, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	data, _ := io.ReadAll(resp.Body)
	return rpcResponse{StatusCode: resp.StatusCode, Header: resp.Header}, string(data)
}

type seen struct {
	scopes []string
	token  string
	nilled bool
}

// sessionServer runs AuthMiddleware around a real streamable handler, with one tool that
// records what its context says.
func sessionServer(t *testing.T, e *testEnv, wire bool, wrap func(http.Handler) http.Handler) (string, *seen) {
	t.Helper()
	got := &seen{}
	s := mcp.NewServer(&mcp.Implementation{Name: "x", Version: "1"}, nil)
	if wire {
		s.AddReceivingMiddleware(e.adapter.ReceivingMiddleware())
	}
	mcp.AddTool(s, &mcp.Tool{Name: "secret"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		c := authplanemcp.ClaimsFromContext(ctx)
		got.nilled = c == nil
		if c != nil {
			got.scopes = c.Scopes()
		}
		got.token = authplanemcp.TokenFromContext(ctx)
		return &mcp.CallToolResult{}, nil, nil
	})
	var h http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
	if wrap != nil {
		h = wrap(h)
	}
	srv := httptest.NewServer(e.adapter.AuthMiddleware(h))
	t.Cleanup(srv.Close)
	return srv.URL, got
}

const toolCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secret","arguments":{}}}`

func TestSession_ToolSeesCurrentTokenWithMiddleware_A65(t *testing.T) {
	e := newTestEnv(t)
	url, got := sessionServer(t, e, true, nil)
	broad := e.makeToken(t, []string{"admin", "read"}, time.Now().Add(time.Hour))
	narrow := e.makeToken(t, []string{"read"}, time.Now().Add(2*time.Hour))

	resp, _ := rpc(t, url, broad, "", initBody, nil)
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatalf("no session: %d", resp.StatusCode)
	}
	rpc(t, url, narrow, session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)
	resp, body := rpc(t, url, narrow, session, toolCall, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("call: %d %s", resp.StatusCode, body)
	}
	if len(got.scopes) != 1 || got.scopes[0] != "read" {
		t.Errorf("scopes = %v, want the narrow token's", got.scopes)
	}
	if got.token != narrow {
		t.Error("TokenFromContext returned another request's token")
	}
}

func TestSession_NoMiddlewareReadsNilNotStale_A65(t *testing.T) {
	e := newTestEnv(t)
	url, got := sessionServer(t, e, false, nil)
	broad := e.makeToken(t, []string{"admin"}, time.Now().Add(time.Hour))
	narrow := e.makeToken(t, []string{"read"}, time.Now().Add(2*time.Hour))

	resp, _ := rpc(t, url, broad, "", initBody, nil)
	session := resp.Header.Get("Mcp-Session-Id")
	rpc(t, url, narrow, session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)
	rpc(t, url, narrow, session, toolCall, nil)
	if !got.nilled {
		t.Errorf("scopes = %v, want nil claims rather than the first request's", got.scopes)
	}
	if got.token != "" {
		t.Error("TokenFromContext returned the first request's token")
	}
	var claims *verifier.VerifiedClaims
	if claims.RequireScope("admin") == nil {
		t.Error("nil claims must not satisfy a scope")
	}
}

func TestRejectionBodyHoldsNoVerifierText_A65(t *testing.T) {
	e := newTestEnv(t)
	url, _ := sessionServer(t, e, true, nil)
	resp, body := rpc(t, url, "not.a.jwt", "", initBody, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if strings.Contains(body, "verifier") || strings.Contains(body, "jose") {
		t.Errorf("body = %q", body)
	}
}

func TestClockSkewAndNoToken_A58_A66(t *testing.T) {
	e := newTestEnv(t)
	url, _ := sessionServer(t, e, true, nil)
	withinSkew := e.makeToken(t, []string{"read"}, time.Now().Add(-10*time.Second))
	if resp, body := rpc(t, url, withinSkew, "", initBody, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("within skew: %d %s", resp.StatusCode, body)
	}
	resp, _ := rpc(t, url, "", "", initBody, nil)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `resource_metadata="`) {
		t.Errorf("no token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

func TestProtocol20260728Stateless_A57(t *testing.T) {
	e := newTestEnv(t)
	s := mcp.NewServer(&mcp.Implementation{Name: "x", Version: "1"}, nil)
	var seenScopes []string
	mcp.AddTool(s, &mcp.Tool{Name: "secret"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		seenScopes = authplanemcp.ClaimsFromContext(ctx).Scopes()
		return &mcp.CallToolResult{}, nil, nil
	})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true})
	srv := httptest.NewServer(e.adapter.AuthMiddleware(h))
	t.Cleanup(srv.Close)
	token := e.makeToken(t, []string{"read"}, time.Now().Add(time.Hour))

	const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"}}`
	resp, body := rpc(t, srv.URL, token, "", `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+meta+`}}`, map[string]string{
		"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover",
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "2026-07-28") {
		t.Fatalf("discover: %d %s", resp.StatusCode, body)
	}
	resp, body = rpc(t, srv.URL, token, "", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secret","arguments":{},`+meta+`}}`, map[string]string{
		"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "secret",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("call: %d %s", resp.StatusCode, body)
	}
	if len(seenScopes) != 1 || seenScopes[0] != "read" {
		t.Errorf("scopes = %v", seenScopes)
	}
}

func TestAppChallengePassesThrough_A66(t *testing.T) {
	e := newTestEnv(t)
	const challenge = `Bearer error="invalid_token", error_description="a, b", scope="x"`
	h := e.adapter.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+e.makeToken(t, []string{"read"}, time.Now().Add(time.Hour)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("WWW-Authenticate"); got != challenge {
		t.Errorf("challenge = %q, want it unchanged", got)
	}
}

func TestRequireToolScopes_A63_A64_A78(t *testing.T) {
	e := newTestEnv(t)
	ran := false
	var bodySeen string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ran = true
		data, _ := io.ReadAll(r.Body)
		bodySeen = string(data)
	})
	h := e.adapter.AuthMiddleware(e.adapter.RequireToolScopes(map[string][]string{"secret": {"admin"}})(next))

	call := func(token, body string, headers map[string]string) *httptest.ResponseRecorder {
		ran = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	narrow := e.makeToken(t, []string{"read"}, time.Now().Add(time.Hour))
	admin := e.makeToken(t, []string{"admin"}, time.Now().Add(time.Hour))

	rec := call(narrow, toolCall, map[string]string{"Mcp-Name": "open"})
	if rec.Code != http.StatusForbidden || ran {
		t.Errorf("missing scope: %d, ran=%v", rec.Code, ran)
	}
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	for _, want := range []string{`error="insufficient_scope"`, `scope="admin"`, `resource_metadata="`} {
		if !strings.Contains(wwwAuth, want) {
			t.Errorf("challenge %q lacks %s", wwwAuth, want)
		}
	}
	if rec := call(admin, toolCall, nil); rec.Code != http.StatusOK || !ran {
		t.Errorf("with scope: %d, ran=%v", rec.Code, ran)
	}
	if bodySeen != toolCall {
		t.Errorf("the tool handler read %q, want the original body", bodySeen)
	}
	for name, body := range map[string]string{
		"batch":        `[` + toolCall + `]`,
		"malformed":    `{`,
		"case variant": `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open","Name":"secret"}}`,
		"lone Name":    `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"Name":"secret"}}`,
		"METHOD":       `{"jsonrpc":"2.0","id":2,"METHOD":"tools/call","method":"x","params":{"name":"secret"}}`,
		"duplicate":    `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open","name":"secret"}}`,
	} {
		if rec := call(admin, body, nil); rec.Code != http.StatusBadRequest || ran {
			t.Errorf("%s: %d, ran=%v", name, rec.Code, ran)
		}
	}
}

func TestOutageAnswers503_A66(t *testing.T) {
	e := newTestEnv(t)
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		DefaultTTL: time.Hour,
		FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, errors.New("down")
		},
	})
	t.Cleanup(jc.Close)
	res, err := resource.New(testResource, e.issuer, jc)
	if err != nil {
		t.Fatal(err)
	}
	a, err := authplanemcp.NewAdapterFromClientAndResource(e.adapter.Client(), res)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+e.makeToken(t, []string{"read"}, time.Now().Add(time.Hour)))
	rec := httptest.NewRecorder()
	a.AuthMiddleware(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

// An outage logs at Error; a caller who left answers the same 503 and logs nothing there.
func TestDepartedCallerIsNotLoggedAsOutage_A85(t *testing.T) {
	e := newTestEnv(t)
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		DefaultTTL: time.Hour,
		FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, errors.New("down")
		},
	})
	t.Cleanup(jc.Close)
	res, err := resource.New(testResource, e.issuer, jc)
	if err != nil {
		t.Fatal(err)
	}
	a, err := authplanemcp.NewAdapterFromClientAndResource(e.adapter.Client(), res)
	if err != nil {
		t.Fatal(err)
	}
	token := e.makeToken(t, []string{"read"}, time.Now().Add(time.Hour))
	send := func(ctx context.Context) (int, string) {
		var logs bytes.Buffer
		old := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		defer slog.SetDefault(old)
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		a.AuthMiddleware(okHandler()).ServeHTTP(rec, req)
		return rec.Code, logs.String()
	}
	gone, cancel := context.WithCancel(t.Context())
	cancel()
	if code, logged := send(gone); code != http.StatusServiceUnavailable || strings.Contains(logged, "level=ERROR") {
		t.Errorf("departed: status %d, log %q", code, logged)
	}
	if code, logged := send(t.Context()); code != http.StatusServiceUnavailable || !strings.Contains(logged, "level=ERROR") {
		t.Errorf("outage: status %d, log %q", code, logged)
	}
}
