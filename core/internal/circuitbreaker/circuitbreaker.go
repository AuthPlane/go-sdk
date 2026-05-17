// Package circuitbreaker implements a simple failure-count circuit breaker.
package circuitbreaker

import (
	"sync"
	"time"
)

type state int

const (
	stateClosed state = iota
	stateOpen
	stateHalfOpen
)

// CircuitBreaker protects against cascading failures when the AS is unavailable.
type CircuitBreaker struct {
	threshold int
	cooldown  time.Duration

	mu            sync.Mutex
	state         state
	failures      int
	openedAt      time.Time
	probeInFlight bool
}

// New creates a CircuitBreaker with the given failure threshold and cooldown duration.
func New(threshold int, cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		cooldown:  cooldown,
		state:     stateClosed,
	}
}

// Allow returns true if a request should be attempted.
// In HALF_OPEN state, only one probe request is allowed at a time.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.effectiveState() {
	case stateClosed:
		return true
	case stateOpen:
		return false
	case stateHalfOpen:
		if cb.state != stateHalfOpen {
			cb.state = stateHalfOpen
		}
		if cb.probeInFlight {
			return false
		}
		cb.probeInFlight = true
		return true
	}
	return false
}

// RecordSuccess records a successful operation. Resets the circuit to CLOSED.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	cb.state = stateClosed
	cb.probeInFlight = false
}

// RecordFailure records a failed operation. May open the circuit.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	effective := cb.effectiveState()

	// Failed half-open probe → immediately re-open.
	if cb.probeInFlight && (effective == stateHalfOpen || cb.state == stateHalfOpen) {
		cb.state = stateOpen
		cb.openedAt = time.Now()
		cb.probeInFlight = false
		cb.failures = cb.threshold
		return
	}

	// Ignore stale failures that arrive after cooldown but before a probe.
	if effective == stateHalfOpen && cb.state == stateOpen {
		return
	}

	cb.failures++
	if cb.failures >= cb.threshold {
		cb.state = stateOpen
		cb.openedAt = time.Now()
	}
	cb.probeInFlight = false
}

// State returns the current effective state as a string.
func (cb *CircuitBreaker) State() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.effectiveState() {
	case stateClosed:
		return "closed"
	case stateOpen:
		return "open"
	case stateHalfOpen:
		return "half_open"
	}
	return "unknown"
}

// effectiveState returns the logical state, computing HALF_OPEN lazily.
// Must be called with cb.mu held.
func (cb *CircuitBreaker) effectiveState() state {
	if cb.state == stateOpen && time.Since(cb.openedAt) >= cb.cooldown {
		return stateHalfOpen
	}
	return cb.state
}
