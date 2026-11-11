package authplanemark3labs

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	sessionIDPrefix  = "mcp-session-"
	sessionHeader    = "Mcp-Session-Id"
	protocolHeader   = "MCP-Protocol-Version"
	minSessionKeyLen = 32
)

// sessionBinder mints session IDs that carry a keyed hash of the caller's client and sub, and refuses
// a session ID not minted for the caller. It keeps no state, so it works across replicas
// that share the key.
type sessionBinder struct {
	logger       *slog.Logger
	key          []byte
	allowUnbound bool
}

func newSessionBinder(key []byte, allowUnbound bool) (*sessionBinder, error) {
	switch {
	case len(key) == 0:
		key = make([]byte, minSessionKeyLen)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("authplanemark3labs: session key: %w", err)
		}
	case len(key) < minSessionKeyLen:
		return nil, fmt.Errorf("authplanemark3labs: SessionKey must be at least %d bytes", minSessionKeyLen)
	}
	return &sessionBinder{key: key, allowUnbound: allowUnbound}, nil
}

func (b *sessionBinder) mac(sub, nonce string) string {
	h := hmac.New(sha256.New, b.key)
	_, _ = fmt.Fprintf(h, "%d:%s:%s", len(sub), sub, nonce)
	return hex.EncodeToString(h.Sum(nil))
}

func (b *sessionBinder) mint(sub string) string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce) // crypto/rand.Read never returns an error on supported platforms
	n := hex.EncodeToString(nonce)
	return sessionIDPrefix + n + "." + b.mac(sub, n)
}

func (b *sessionBinder) minted(id string) (nonce, mac string, ok bool) {
	rest, hasPrefix := strings.CutPrefix(id, sessionIDPrefix)
	if !hasPrefix {
		return "", "", false
	}
	return strings.Cut(rest, ".")
}

func (b *sessionBinder) log() *slog.Logger {
	if b.logger != nil {
		return b.logger
	}
	return slog.Default()
}

func (b *sessionBinder) boundTo(id, sub string) bool {
	nonce, mac, ok := b.minted(id)
	return ok && hmac.Equal([]byte(mac), []byte(b.mac(sub, nonce)))
}

// guard refuses a legacy session that was not minted for the caller. Requests on protocol
// 2026-07-28 and later have no sessions: mcp-go ignores the header on them.
func (b *sessionBinder) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(sessionHeader)
		if id == "" || b.allowUnbound || isSessionlessProtocol(r) {
			next.ServeHTTP(w, r)
			return
		}
		claims := ClaimsFromContext(r.Context())
		if claims != nil && b.boundTo(id, sessionOwner(claims)) {
			next.ServeHTTP(w, r)
			return
		}
		if _, _, ok := b.minted(id); !ok {
			b.log().WarnContext(r.Context(), "authplanemark3labs: refusing a session ID this adapter did not mint; "+
				"add server.WithSessionIdManagerResolver(adapter.SessionManager()) to the streamable server, or set Options.AllowUnboundSessions")
		} else {
			b.log().DebugContext(r.Context(), "authplanemark3labs: refusing a session not bound to this caller")
		}
		// 404 tells an MCP client to start a new session, and reveals nothing about
		// whether the ID exists. It is also the right answer after a restart on a random key.
		http.Error(w, "session not found", http.StatusNotFound)
	})
}

func isSessionlessProtocol(r *http.Request) bool {
	version := r.Header.Get(protocolHeader)
	return version != "" && version >= mcp.ProtocolVersion20260728
}

// sessionOwner is who a session belongs to: the user and the OAuth client together, so that
// two clients of one user cannot use each other's sessions.
func sessionOwner(claims *verifier.VerifiedClaims) string {
	return claims.ClientID() + "\x00" + claims.Sub()
}

// ResolveSessionIdManager implements server.SessionIdManagerResolver.
func (b *sessionBinder) ResolveSessionIdManager(r *http.Request) server.SessionIdManager { //nolint:revive // the interface names it so
	sub := ""
	if r != nil {
		if claims := ClaimsFromContext(r.Context()); claims != nil {
			sub = sessionOwner(claims)
		}
	}
	return &boundSessionManager{binder: b, sub: sub, hasCaller: r != nil}
}

// boundSessionManager serves one request. mcp-go also resolves one with a nil request to
// close and sweep sessions, when there is no caller to compare against.
type boundSessionManager struct {
	binder    *sessionBinder
	sub       string
	hasCaller bool
}

// Generate implements server.SessionIdManager.
func (m *boundSessionManager) Generate() string {
	return m.binder.mint(m.sub)
}

// Validate implements server.SessionIdManager.
func (m *boundSessionManager) Validate(sessionID string) (isTerminated bool, err error) {
	if !m.hasCaller {
		if _, _, ok := m.binder.minted(sessionID); ok {
			return false, nil
		}
		return false, errors.New("invalid session id")
	}
	if !m.binder.allowUnbound && !m.binder.boundTo(sessionID, m.sub) {
		return false, errors.New("invalid session id")
	}
	return false, nil
}

// Terminate implements server.SessionIdManager.
func (m *boundSessionManager) Terminate(sessionID string) (isNotAllowed bool, err error) {
	if m.hasCaller && !m.binder.allowUnbound && !m.binder.boundTo(sessionID, m.sub) {
		return true, nil
	}
	return false, nil
}
