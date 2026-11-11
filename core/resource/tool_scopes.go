package resource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/authplane/go-sdk/core/resource/verifier"
)

// maxToolCallBody bounds what ToolScopeGuard reads. A larger request is refused.
const maxToolCallBody = 4 << 20

// ToolScopeGuardConfig configures ToolScopeGuard.
type ToolScopeGuardConfig struct {
	// Claims returns the verified claims for a request, or nil.
	Claims func(*http.Request) *verifier.VerifiedClaims
	// ResourceMetadataURL is advertised in the challenge.
	ResourceMetadataURL string
	// ToolScopes maps a tool name to the scopes calling it requires. A tool not listed
	// here passes, and is left to its handler, unless RefuseUnlisted is set.
	ToolScopes map[string][]string
	// RefuseUnlisted answers 403 for a tool not in ToolScopes, so a newly added tool has no
	// access until someone decides its scopes. An empty scope list in ToolScopes allows a tool.
	RefuseUnlisted bool
}

// ToolScopeGuard returns middleware that answers an MCP tools/call missing a required
// scope with HTTP 403 and an insufficient_scope challenge before the tool runs, so a
// client can step up (MCP authorization, runtime insufficient scope).
//
// The tool name comes from the parsed body, never from the client-supplied Mcp-Name
// header. A batch, a body it cannot parse, or one with duplicate or case-variant keys
// is refused, because the guard and the MCP SDK might decode those differently and
// disagree about which tool is being called.
//
// Claims must be set. Without it the guard refuses every tools/call rather than guess.
func ToolScopeGuard(cfg ToolScopeGuardConfig) func(http.Handler) http.Handler {
	if cfg.Claims == nil {
		cfg.Claims = func(*http.Request) *verifier.VerifiedClaims { return nil }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxToolCallBody))
			if err != nil {
				http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			tool, err := toolCallName(body)
			if err != nil {
				http.Error(w, "malformed or unsupported JSON-RPC request", http.StatusBadRequest)
				return
			}
			required, listed := cfg.ToolScopes[tool]
			if tool == "" || (len(required) == 0 && (listed || !cfg.RefuseUnlisted)) {
				next.ServeHTTP(w, r)
				return
			}

			claims := cfg.Claims(r)
			var refusal error
			switch {
			case claims == nil:
				refusal = verifier.ErrTokenMissing
			case !listed:
				refusal = verifier.ErrInsufficientScope
			default:
				if err := claims.RequireScopes(required...); err != nil {
					refusal = &ScopeError{RequiredScopes: required, Err: err}
				}
			}
			if refusal == nil {
				next.ServeHTTP(w, r)
				return
			}
			status, headers, respBody := AuthErrorResponse(refusal, WithChallengeMetadata(cfg.ResourceMetadataURL))
			for k, v := range headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(respBody))
		})
	}
}

// toolCallName returns the tool a JSON-RPC message calls, or "" for any other message.
func toolCallName(body []byte) (string, error) {
	fields, err := strictFields(body, "method", "params")
	if err != nil {
		return "", err
	}
	var method string
	if raw, ok := fields["method"]; ok {
		if err := json.Unmarshal(raw, &method); err != nil {
			return "", fmt.Errorf("method: %w", err)
		}
	}
	if method != "tools/call" {
		return "", nil
	}
	params, err := strictFields(fields["params"], "name")
	if err != nil {
		return "", err
	}
	var name string
	if err := json.Unmarshal(params["name"], &name); err != nil || name == "" {
		return "", errors.New("tools/call has no tool name")
	}
	return name, nil
}

// strictFields decodes a JSON object's members named in watch, refusing a value that is
// not an object and any duplicate or case-variant spelling of a watched name.
func strictFields(data []byte, watch ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	out := make(map[string]json.RawMessage, len(watch))
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		for _, name := range watch {
			if !strings.EqualFold(key, name) {
				continue
			}
			if key != name {
				return nil, fmt.Errorf("case-variant key %q", key)
			}
			if _, dup := out[name]; dup {
				return nil, fmt.Errorf("duplicate key %q", key)
			}
			out[name] = value
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return out, nil
}
