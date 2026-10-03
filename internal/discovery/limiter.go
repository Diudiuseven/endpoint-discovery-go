package discovery

import (
	"context"
	"sync"
	"time"
)

// Limiter enforces a global request rate (token bucket) and a per-target
// concurrency cap (semaphore). Every request — including retries — passes
// through Acquire, so retries consume budget and never amplify traffic.
type Limiter struct {
	mu     sync.Mutex
	tokens float64
	rate   float64 // tokens per second
	burst  float64
	last   time.Time
	sem    chan struct{}
	now    func() time.Time // for tests
}

// NewLimiter creates a Limiter. rps<=0 means unlimited rate; concurrency<=0
// defaults to 1.
func NewLimiter(rps float64, concurrency int) *Limiter {
	if concurrency <= 0 {
		concurrency = 1
	}
	// Burst of 1 token: the first request is immediate and subsequent
	// requests are spaced by 1/rps, so even short scans are rate-limited.
	const burst = 1.0
	return &Limiter{
		tokens: burst,
		rate:   rps,
		burst:  burst,
		last:   time.Now(),
		sem:    make(chan struct{}, concurrency),
		now:    time.Now,
	}
}

// Acquire blocks until both a concurrency slot and (if rate-limited) a token
// are available, or ctx is done.
func (l *Limiter) Acquire(ctx context.Context) error {
	// Concurrency slot first so queued goroutines don't burn rate tokens
	// while waiting for a slot.
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := l.waitToken(ctx); err != nil {
		<-l.sem
		return err
	}
	return nil
}

func (l *Limiter) waitToken(ctx context.Context) error {
	if l.rate <= 0 {
		return nil
	}
	for {
		l.mu.Lock()
		now := l.now()
		elapsed := now.Sub(l.last).Seconds()
		l.last = now
		l.tokens += elapsed * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		deficit := 1 - l.tokens
		l.mu.Unlock()
		wait := time.Duration(deficit / l.rate * float64(time.Second))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Release returns a concurrency slot. Must be called exactly once per
// successful Acquire.
func (l *Limiter) Release() {
	<-l.sem
}

// Backoff computes the delay before retry attempt n (1-based): base * 2^(n-1)
// capped at max. Deterministic (no jitter) so tests and resumed runs are
// reproducible.
func Backoff(base, max time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = 100 * time.Millisecond
	}
	if max <= 0 {
		max = 2 * time.Second
	}
	d := base
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	if d > max {
		return max
	}
	return d
}
