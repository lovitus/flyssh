package main

import (
	"testing"
	"time"
)

func TestReconnectBackoffDefaultsAndResets(t *testing.T) {
	backoff := newReconnectBackoff(0)
	want := []time.Duration{3 * time.Second, 6 * time.Second, 12 * time.Second, 24 * time.Second, 48 * time.Second, time.Minute, time.Minute}
	for i, expected := range want {
		if got := backoff.Next(); got != expected {
			t.Fatalf("attempt %d delay = %v, want %v", i+1, got, expected)
		}
	}
	backoff.Reset()
	if got := backoff.Next(); got != 3*time.Second {
		t.Fatalf("delay after reset = %v, want 3s", got)
	}
}

func TestReconnectBackoffHonorsExplicitInitialDelay(t *testing.T) {
	backoff := newReconnectBackoff(10 * time.Second)
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, time.Minute}
	for i, expected := range want {
		if got := backoff.Next(); got != expected {
			t.Fatalf("attempt %d delay = %v, want %v", i+1, got, expected)
		}
	}
}

func TestReconnectBackoffDoesNotShortenLargeExplicitDelay(t *testing.T) {
	backoff := newReconnectBackoff(2 * time.Minute)
	if got := backoff.Next(); got != 2*time.Minute {
		t.Fatalf("first delay = %v, want 2m", got)
	}
	if got := backoff.Next(); got != 2*time.Minute {
		t.Fatalf("capped delay = %v, want 2m", got)
	}
}
