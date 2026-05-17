package circuitbreaker

import (
	"testing"
	"time"
)

func TestNew_DefaultState(t *testing.T) {
	cb := New(5, 30*time.Second)
	if cb.State() != "closed" {
		t.Errorf("expected closed, got %s", cb.State())
	}
}

func TestAllow_Closed(t *testing.T) {
	cb := New(5, 30*time.Second)
	if !cb.Allow() {
		t.Error("closed circuit should allow requests")
	}
}

func TestRecordFailure_OpensCircuit(t *testing.T) {
	cb := New(3, 30*time.Second)
	for range 3 {
		cb.RecordFailure()
	}
	if cb.State() != "open" {
		t.Errorf("expected open after 3 failures, got %s", cb.State())
	}
	if cb.Allow() {
		t.Error("open circuit should reject requests")
	}
}

func TestRecordFailure_BelowThreshold(t *testing.T) {
	cb := New(5, 30*time.Second)
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != "closed" {
		t.Errorf("expected closed with 2 failures (threshold 5), got %s", cb.State())
	}
	if !cb.Allow() {
		t.Error("should still allow requests below threshold")
	}
}

func TestRecordSuccess_ResetsFailures(t *testing.T) {
	cb := New(3, 30*time.Second)
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()
	// After reset, need 3 more failures to open
	cb.RecordFailure()
	if cb.State() != "closed" {
		t.Error("success should reset failure count")
	}
}

func TestHalfOpen_AfterCooldown(t *testing.T) {
	cb := New(3, 50*time.Millisecond)
	for range 3 {
		cb.RecordFailure()
	}
	if cb.State() != "open" {
		t.Fatalf("expected open, got %s", cb.State())
	}

	time.Sleep(60 * time.Millisecond)

	if cb.State() != "half_open" {
		t.Errorf("expected half_open after cooldown, got %s", cb.State())
	}
}

func TestHalfOpen_OnlyOneProbe(t *testing.T) {
	cb := New(3, 50*time.Millisecond)
	for range 3 {
		cb.RecordFailure()
	}
	time.Sleep(60 * time.Millisecond)

	// First Allow in half-open → probe allowed
	if !cb.Allow() {
		t.Error("first request in half-open should be allowed (probe)")
	}
	// Second Allow → rejected (probe in flight)
	if cb.Allow() {
		t.Error("second request in half-open should be rejected (probe in flight)")
	}
}

func TestHalfOpen_ProbeSuccess_CloseCircuit(t *testing.T) {
	cb := New(3, 50*time.Millisecond)
	for range 3 {
		cb.RecordFailure()
	}
	time.Sleep(60 * time.Millisecond)

	cb.Allow() // probe admitted
	cb.RecordSuccess()

	if cb.State() != "closed" {
		t.Errorf("expected closed after probe success, got %s", cb.State())
	}
	if !cb.Allow() {
		t.Error("circuit should be closed and allow requests")
	}
}

func TestHalfOpen_ProbeFailure_ReopenCircuit(t *testing.T) {
	cb := New(3, 50*time.Millisecond)
	for range 3 {
		cb.RecordFailure()
	}
	time.Sleep(60 * time.Millisecond)

	cb.Allow() // probe admitted
	cb.RecordFailure()

	if cb.State() != "open" {
		t.Errorf("expected open after probe failure, got %s", cb.State())
	}
	if cb.Allow() {
		t.Error("circuit should be open and reject requests")
	}
}

func TestRecordSuccess_FromOpen(t *testing.T) {
	cb := New(3, 30*time.Second)
	for range 3 {
		cb.RecordFailure()
	}
	cb.RecordSuccess()
	if cb.State() != "closed" {
		t.Errorf("expected closed after success, got %s", cb.State())
	}
}

func TestMultipleCycles(t *testing.T) {
	cb := New(2, 50*time.Millisecond)

	// Cycle 1: open
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != "open" {
		t.Fatal("expected open")
	}

	// Wait for half-open, probe succeeds
	time.Sleep(60 * time.Millisecond)
	cb.Allow()
	cb.RecordSuccess()
	if cb.State() != "closed" {
		t.Fatal("expected closed after probe success")
	}

	// Cycle 2: open again
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != "open" {
		t.Fatal("expected open again")
	}

	// Wait for half-open, probe fails
	time.Sleep(60 * time.Millisecond)
	cb.Allow()
	cb.RecordFailure()
	if cb.State() != "open" {
		t.Fatal("expected open after probe failure")
	}
}
