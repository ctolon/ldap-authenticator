package ldapauth

import (
	"context"
	"sync"
	"sync/atomic"
)

// inflight collapses concurrent authentications of the same credential
// into one directory round trip.
//
// The case it exists for is HTTP Basic auth in front of a chatty API: a
// browser or a mobile client sends the same header on every request, and a
// hundred of them arriving at once become a hundred simultaneous binds
// against a directory that would rather have one. The cache absorbs the
// second and later attempts, but only once the first has finished — the
// stampede happens in the window before that, and this is what closes it.
//
// Sharing is safe because the key already covers the whole credential:
// two callers that collapse into one are two callers who presented exactly
// the same username and password, and the answer for one is the answer for
// the other. Waiters are given a clone, not the shared value.
//
// It is only used when caching is enabled. Without a cache there is
// nothing to protect: every request is meant to reach the directory.
type inflight struct {
	mu    sync.Mutex
	calls map[string]*flightCall
}

type flightCall struct {
	done chan struct{}

	// waiters counts the callers attached to this call. It exists so that
	// the coalescing can be observed — by a test that needs to know every
	// waiter has arrived before letting the leader finish, and by anyone
	// asking how much of a stampede is being absorbed.
	waiters atomic.Int64

	identity Identity

	err error
}

func newInflight() *inflight {
	return &inflight{calls: make(map[string]*flightCall)}
}

// do runs fn, or waits for the fn already running under the same key and
// returns a clone of its result.
//
// shared reports whether this call waited on somebody else's work, which
// the metrics hook uses to say how much of the stampede was absorbed.
//
// A waiter never outlives its own context: if the caller gives up, it
// stops waiting and says so, and the flight carries on for whoever else is
// attached to it. What a waiter cannot do is get a better answer than the
// leader got — if the leader's attempt failed, that failure is what
// everybody attached to it receives.
func (f *inflight) do(ctx context.Context, key string, fn func() (Identity, error)) (identity Identity, shared bool, err error) {
	f.mu.Lock()

	if call, ok := f.calls[key]; ok {
		call.waiters.Add(1)
		f.mu.Unlock()

		select {
		case <-call.done:
		case <-ctx.Done():
			// Detach, so that the count keeps meaning "attached now"
			// rather than "attached at some point".
			call.waiters.Add(-1)

			return nil, true, ctx.Err()
		}

		if call.err != nil {
			return nil, true, call.err
		}

		if call.identity == nil {
			return nil, true, nil
		}

		return call.identity.Clone(), true, nil
	}

	call := &flightCall{done: make(chan struct{})}
	f.calls[key] = call
	f.mu.Unlock()

	// The leader must publish a result even if fn panics, or every waiter
	// blocks forever on a channel nobody will close. The panic still
	// propagates to the leader's own caller.
	defer func() {
		f.mu.Lock()
		delete(f.calls, key)
		f.mu.Unlock()

		close(call.done)
	}()

	call.identity, call.err = fn()

	if call.err != nil {
		return nil, false, call.err
	}

	if call.identity == nil {
		return nil, false, nil
	}

	return call.identity.Clone(), false, nil
}

// waiting reports how many callers are attached to the flight under key,
// not counting the one running it. It is zero for a key with nothing in
// flight.
func (f *inflight) waiting(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	call, ok := f.calls[key]
	if !ok {
		return 0
	}

	return int(call.waiters.Load())
}
