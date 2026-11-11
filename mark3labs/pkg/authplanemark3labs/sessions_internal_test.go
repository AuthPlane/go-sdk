package authplanemark3labs

import (
	"strings"
	"testing"

	"github.com/authplane/go-sdk/core/resource/verifier/verifiertest"
)

// Terminate must refuse a session minted for someone else, whatever the guard in front does.
func TestBoundSessionManager_TerminateChecksTheBinding_A93(t *testing.T) {
	binder, err := newSessionBinder([]byte(strings.Repeat("k", minSessionKeyLen)), false)
	if err != nil {
		t.Fatal(err)
	}
	alice := binder.mint("alice")
	bob := &boundSessionManager{binder: binder, sub: "bob", hasCaller: true}
	if notAllowed, err := bob.Terminate(alice); err != nil || !notAllowed {
		t.Errorf("bob ending alice's session: notAllowed=%v err=%v", notAllowed, err)
	}
	owner := &boundSessionManager{binder: binder, sub: "alice", hasCaller: true}
	if notAllowed, err := owner.Terminate(alice); err != nil || notAllowed {
		t.Errorf("alice ending her own session: notAllowed=%v err=%v", notAllowed, err)
	}
}

// Two clients of one user must not use each other's sessions.
func TestSessionOwner_SeparatesClientsOfOneUser_A104(t *testing.T) {
	one, err := verifiertest.NewClaims(map[string]any{"sub": "u", "client_id": "one"})
	if err != nil {
		t.Fatal(err)
	}
	two, err := verifiertest.NewClaims(map[string]any{"sub": "u", "client_id": "two"})
	if err != nil {
		t.Fatal(err)
	}
	binder, err := newSessionBinder([]byte(strings.Repeat("k", minSessionKeyLen)), false)
	if err != nil {
		t.Fatal(err)
	}
	id := binder.mint(sessionOwner(one))
	if !binder.boundTo(id, sessionOwner(one)) {
		t.Error("the owner must pass")
	}
	if binder.boundTo(id, sessionOwner(two)) {
		t.Error("another client of the same user must not pass")
	}
}
