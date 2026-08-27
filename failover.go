package ldapauth

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// FailoverPolicy decides the order in which configured servers are tried.
type FailoverPolicy int

const (
	// FailoverInOrder tries the configured URLs in the order they were
	// given, always starting from the first healthy one. This is the
	// default, and it is what you want when the list is ordered by
	// preference — a local replica first, a remote one behind it.
	FailoverInOrder FailoverPolicy = iota

	// FailoverRoundRobin starts each attempt at the next URL in sequence,
	// spreading load across the healthy servers. Use it when the servers
	// are equivalent and you would rather not send every bind in the fleet
	// to the same replica.
	FailoverRoundRobin

	// FailoverRandom starts each attempt at a uniformly random URL. Like
	// round robin, but without the shared counter — worth having when many
	// processes share one server list and starting them in lockstep would
	// synchronise their round robins.
	FailoverRandom
)

// String returns a stable, lower-case name for the policy, suitable for
// a log field or a metrics label.
func (p FailoverPolicy) String() string {
	switch p {
	case FailoverInOrder:
		return "in-order"
	case FailoverRoundRobin:
		return "round-robin"
	case FailoverRandom:
		return "random"
	default:
		return fmt.Sprintf("FailoverPolicy(%d)", int(p))
	}
}

func (p FailoverPolicy) valid() bool {
	return p >= FailoverInOrder && p <= FailoverRandom
}

// serverSet tracks the configured URLs and which of them are currently
// believed to be down.
//
// The health state is deliberately crude: a URL that fails to dial is
// skipped for a cooldown, then tried again. There is no half-open state
// and no success threshold, because there is nothing to protect here — a
// failed dial costs a TCP timeout, not a cascade. What the cooldown buys
// is that a two-server deployment with one server down does not pay that
// timeout on every single login.
type serverSet struct {
	urls     []string
	policy   FailoverPolicy
	cooldown time.Duration
	now      func() time.Time

	// cursor drives FailoverRoundRobin. It is only ever incremented, and
	// wraps naturally on the modulo.
	cursor atomic.Uint64

	mu        sync.Mutex
	downUntil []time.Time
}

func newServerSet(urls []string, policy FailoverPolicy, cooldown time.Duration, now func() time.Time) *serverSet {
	return &serverSet{
		urls:      urls,
		policy:    policy,
		cooldown:  cooldown,
		now:       now,
		downUntil: make([]time.Time, len(urls)),
	}
}

// dial opens a connection to the first server that will accept one,
// returning the connection and the URL it belongs to.
//
// Every URL is tried before the call fails, including URLs inside their
// cooldown: the cooldown reorders the attempts, it never removes a server
// from the list. A cooldown that could take the last server out of
// rotation would turn a slow directory into a hard outage.
func (s *serverSet) dial(ctx context.Context, d Dialer) (Conn, string, error) {
	order := s.order()

	var errs []error

	for _, i := range order {
		if err := ctx.Err(); err != nil {
			return nil, "", fmt.Errorf("ldapauth: dial: %w", err)
		}

		conn, err := d.DialContext(ctx, s.urls[i])
		if err == nil {
			s.markUp(i)

			return conn, s.urls[i], nil
		}

		s.markDown(i)
		errs = append(errs, err)

		// A cancelled or expired context is the caller giving up, not a
		// server being unreachable. Trying the next one would only make
		// the error less accurate.
		if ctx.Err() != nil {
			break
		}
	}

	return nil, "", fmt.Errorf("%w: %w", ErrNoServerAvailable, errors.Join(errs...))
}

// order returns the indices to try, healthy servers first, each group in
// the order the policy asks for.
func (s *serverSet) order() []int {
	start := 0

	switch s.policy {
	case FailoverRoundRobin:
		start = int(s.cursor.Add(1)-1) % len(s.urls)
	case FailoverRandom:
		start = rand.IntN(len(s.urls))
	case FailoverInOrder:
	}

	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	healthy := make([]int, 0, len(s.urls))
	cooling := make([]int, 0, len(s.urls))

	for offset := range s.urls {
		i := (start + offset) % len(s.urls)

		if now.Before(s.downUntil[i]) {
			cooling = append(cooling, i)

			continue
		}

		healthy = append(healthy, i)
	}

	return append(healthy, cooling...)
}

// penalise marks a URL down after a failure that happened *after* the
// connection was established.
//
// Dialling is not the only way a server fails. One that accepts a TCP
// connection, completes a TLS handshake, and then cannot answer a bind or
// a search is a server this package would otherwise keep choosing first,
// for as long as the cooldown never started — which is the failure mode
// where a URL list stops being failover and becomes decoration.
//
// Only failures worth retrying reach here. A rejected credential says
// nothing about the server, and penalising on one would let a user with a
// wrong password take a healthy replica out of rotation.
func (s *serverSet) penalise(url string) {
	if url == "" {
		return
	}

	for i, candidate := range s.urls {
		if candidate == url {
			s.markDown(i)

			return
		}
	}
}

func (s *serverSet) markDown(i int) {
	if s.cooldown <= 0 {
		return
	}

	until := s.now().Add(s.cooldown)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.downUntil[i] = until
}

func (s *serverSet) markUp(i int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.downUntil[i] = time.Time{}
}

// healthy reports how many servers are not currently in a cooldown. Stats
// reports it; nothing branches on it.
func (s *serverSet) healthy() int {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0

	for _, until := range s.downUntil {
		if !now.Before(until) {
			n++
		}
	}

	return n
}
