package main

import "time"

const (
	defaultReconnectDelay = 3 * time.Second
	minimumReconnectCap   = time.Minute
)

type reconnectBackoff struct {
	base    time.Duration
	cap     time.Duration
	attempt int
}

func newReconnectBackoff(base time.Duration) *reconnectBackoff {
	if base <= 0 {
		base = defaultReconnectDelay
	}
	cap := minimumReconnectCap
	if base > cap {
		cap = base
	}
	return &reconnectBackoff{base: base, cap: cap}
}

// Next returns the wait before the next reconnect attempt. The first failed
// route waits base, then doubles until cap. A fully connected route calls
// Reset so later unrelated failures start promptly again.
func (b *reconnectBackoff) Next() time.Duration {
	if b == nil {
		return defaultReconnectDelay
	}
	delay := b.base
	for i := 0; i < b.attempt && delay < b.cap; i++ {
		if delay > b.cap/2 {
			delay = b.cap
			break
		}
		delay *= 2
	}
	b.attempt++
	return delay
}

func (b *reconnectBackoff) Reset() {
	if b != nil {
		b.attempt = 0
	}
}
