package ldapauth

import (
	"context"
	"time"
)

// operate runs one LDAP operation with the caller's context in charge of
// it.
//
// go-ldap's operations are synchronous and take no context: Bind, Search
// and WhoAmI block until the server answers or the connection's own
// timeout fires. On its own that leaves two holes. A caller who has given
// up — the HTTP request was cancelled, the process is shutting down —
// keeps a goroutine and a pooled connection occupied until that timeout;
// and with WithOperationTimeout(0) there is no timeout to wait for.
//
// So each operation runs on its own goroutine and is raced against the
// context. Two things follow, and both matter:
//
// The connection's timeout is set per operation to whichever is sooner,
// the configured operation timeout or what is left of the caller's
// deadline. A request with 200ms remaining does not sit in a ten-second
// read.
//
// When the context wins, the connection is closed. That is the only way to
// unblock a goroutine parked in a go-ldap read, and it is also the right
// outcome: a connection with an abandoned operation on it must never carry
// the next request, because the answer to the abandoned one may still be
// in flight. The pool discards it, because release discards on any error
// and a cancellation is an error.
func (a *Client) operate(ctx context.Context, conn Conn, fn func() error) error {
	return operate(ctx, a.cfg, conn, fn)
}

// operate is the same, without a Client.
//
// The pool needs it too — its service bind and its health probe are LDAP
// operations like any other, and for a release they were not treated as
// such: both called through to go-ldap directly, so a caller with fifty
// milliseconds left could block for the full operation timeout inside
// acquire and could not be cancelled at all. That is the pool's half of
// the bug the rest of this file exists to fix.
func operate(ctx context.Context, cfg *config, conn Conn, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	timeout, expired := cfg.effectiveTimeout(ctx)
	if expired {
		return context.DeadlineExceeded
	}

	if timeout > 0 {
		conn.SetTimeout(timeout)
	}

	// Buffered, so that the goroutine can always publish its result and
	// exit even when nobody is left to read it.
	done := make(chan error, 1)

	go func() { done <- fn() }()

	select {
	case err := <-done:
		return err

	case <-ctx.Done():
		_ = conn.Close()
		cfg.metrics.ConnClosed("cancelled")

		return ctx.Err()
	}
}

// effectiveTimeout is how long a single operation may take: the smaller of
// the configured operation timeout and what remains of the caller's
// deadline.
//
// expired reports a deadline that has already passed, which is not the
// same as a context that has already been cancelled — a deadline one
// microsecond away has not fired yet, and starting a ten-second read
// against it would be worse than saying so.
func (c *config) effectiveTimeout(ctx context.Context) (timeout time.Duration, expired bool) {
	timeout = c.operationTimeout

	deadline, ok := ctx.Deadline()
	if !ok {
		return timeout, false
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, true
	}

	if timeout <= 0 || remaining < timeout {
		timeout = remaining
	}

	return timeout, false
}
