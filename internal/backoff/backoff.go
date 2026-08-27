// Package backoff computes retry delays.
//
// It exists as its own package so that the delay arithmetic — the part
// that is easy to get subtly wrong and easy to test in isolation — is not
// tangled up with the LDAP error classification that decides whether to
// retry at all.
package backoff

import (
	"math"
	"math/rand/v2"
	"time"
)

// Policy describes a capped exponential backoff with full jitter.
//
// Full jitter, rather than the exponential delay itself or the delay plus
// a small random nudge, is what actually decorrelates a fleet of clients
// that all lost their directory at the same instant: every waiter picks
// uniformly from [0, delay), so the retries spread across the window
// instead of arriving together at the end of it.
type Policy struct {
	// Base is the delay before the first retry. Subsequent delays grow
	// from it by Multiplier.
	Base time.Duration

	// Max caps a single delay, however many attempts have failed.
	Max time.Duration

	// Multiplier is the growth factor between attempts. Values below 1
	// are treated as 1, which turns the policy into a constant delay.
	Multiplier float64
}

// Delay returns how long to wait before attempt number n, where n counts
// from 1 for the first retry. A non-positive n returns zero.
//
// The caller is expected to sample once per retry and to select on its
// context while waiting; Delay does no waiting of its own and touches no
// clock, which is why it is trivially testable.
func (p Policy) Delay(n int) time.Duration {
	if n <= 0 || p.Base <= 0 {
		return 0
	}

	multiplier := p.Multiplier
	if multiplier < 1 {
		multiplier = 1
	}

	// math.Pow on a float64 nanosecond count overflows into +Inf well
	// before it overflows the int64 it is converted to, so the growth is
	// clamped before the conversion rather than after it.
	grown := float64(p.Base) * math.Pow(multiplier, float64(n-1))

	ceiling := float64(p.Max)
	if p.Max <= 0 || grown < ceiling {
		ceiling = grown
	}

	if ceiling > float64(math.MaxInt64) {
		ceiling = float64(math.MaxInt64)
	}

	capped := time.Duration(ceiling)
	if capped <= 0 {
		return 0
	}

	return time.Duration(rand.Int64N(int64(capped)) + 1)
}
