package backoff

import (
	"math"
	"testing"
	"time"
)

func TestDelayStaysInsideTheEnvelope(t *testing.T) {
	t.Parallel()

	p := Policy{Base: 100 * time.Millisecond, Max: time.Second, Multiplier: 2}

	envelopes := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		time.Second,
		time.Second,
	}

	for attempt, envelope := range envelopes {
		for range 200 {
			d := p.Delay(attempt + 1)

			if d <= 0 {
				t.Fatalf("Delay(%d) = %s, want a positive delay", attempt+1, d)
			}

			if d > envelope {
				t.Fatalf("Delay(%d) = %s, above the envelope of %s", attempt+1, d, envelope)
			}
		}
	}
}

func TestDelayIsJittered(t *testing.T) {
	t.Parallel()

	// Full jitter is the whole point: without it, a fleet that lost the
	// directory at the same instant comes back at the same instant.
	p := Policy{Base: time.Second, Max: time.Minute, Multiplier: 2}

	seen := map[time.Duration]struct{}{}

	for range 100 {
		seen[p.Delay(3)] = struct{}{}
	}

	if len(seen) < 50 {
		t.Errorf("100 samples produced %d distinct delays, want a spread", len(seen))
	}
}

func TestDelayOfANonPositiveAttemptIsZero(t *testing.T) {
	t.Parallel()

	p := Policy{Base: time.Second, Max: time.Minute, Multiplier: 2}

	for _, n := range []int{0, -1, -1000} {
		if d := p.Delay(n); d != 0 {
			t.Errorf("Delay(%d) = %s, want 0", n, d)
		}
	}
}

func TestZeroPolicyDelaysNothing(t *testing.T) {
	t.Parallel()

	if d := (Policy{}).Delay(1); d != 0 {
		t.Errorf("Delay on the zero policy = %s, want 0", d)
	}
}

func TestLargeAttemptCountsDoNotOverflow(t *testing.T) {
	t.Parallel()

	// math.Pow reaches +Inf long before the int64 conversion would
	// saturate, and an unclamped conversion of +Inf is undefined.
	p := Policy{Base: time.Second, Max: time.Minute, Multiplier: 2}

	for _, n := range []int{64, 1000, math.MaxInt32} {
		d := p.Delay(n)

		if d <= 0 || d > time.Minute {
			t.Errorf("Delay(%d) = %s, want a positive delay no greater than the cap", n, d)
		}
	}
}

func TestAMultiplierBelowOneIsAConstantDelay(t *testing.T) {
	t.Parallel()

	p := Policy{Base: time.Second, Max: time.Minute, Multiplier: 0}

	for attempt := 1; attempt <= 10; attempt++ {
		if d := p.Delay(attempt); d > time.Second {
			t.Fatalf("Delay(%d) = %s, want no growth from a multiplier below 1", attempt, d)
		}
	}
}
