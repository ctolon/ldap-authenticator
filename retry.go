package ldapauth

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// retriable reports whether an error is worth another attempt.
//
// The list is short on purpose. A retry is only correct when the failure
// says nothing about whether the operation would succeed — the connection
// broke, the server is busy, the server is going down. Everything else is
// an answer, and repeating the question does not change it.
//
// ErrInvalidCredentials is the one that matters. Directories with a
// lockout policy count failed binds, so a library that retried a rejected
// password would turn one typo into three strikes and lock the account
// out. This package never retries a bind that the directory answered.
func retriable(err error) bool {
	if err == nil {
		return false
	}

	// The caller giving up is not a transient failure.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	if errors.Is(err, ErrInvalidCredentials) ||
		errors.Is(err, ErrEmptyPassword) ||
		errors.Is(err, ErrEmptyUsername) ||
		errors.Is(err, ErrInvalidUsername) ||
		errors.Is(err, ErrUserNotFound) ||
		errors.Is(err, ErrAmbiguousUser) ||
		errors.Is(err, ErrClosed) {
		return false
	}

	if errors.Is(err, ErrNoServerAvailable) || errors.Is(err, ErrPoolExhausted) {
		return true
	}

	if ldap.IsErrorAnyOf(err,
		ldap.LDAPResultBusy,
		ldap.LDAPResultUnavailable,
		ldap.LDAPResultTimeLimitExceeded,
		ldap.ErrorNetwork,
		ldap.ErrorUnexpectedMessage,
		ldap.ErrorUnexpectedResponse,
	) {
		return true
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}

	var nerr net.Error
	if errors.As(err, &nerr) {
		return nerr.Timeout()
	}

	return false
}

// withRetry runs fn until it succeeds, until the error is one that will
// not change, or until the attempt or elapsed-time budget runs out.
//
// The elapsed budget is checked before sleeping rather than after, so a
// policy that would sleep past its own deadline gives up immediately
// instead of sleeping and then reporting that it is out of time.
func (a *Client) withRetry(ctx context.Context, op string, fn func(context.Context) error) error {
	started := a.cfg.now()

	var err error

	for attempt := 0; ; attempt++ {
		err = fn(ctx)
		if err == nil {
			return nil
		}

		if !retriable(err) || attempt >= a.cfg.retryMaxAttempts {
			break
		}

		delay := a.cfg.backoff.Delay(attempt + 1)

		if a.cfg.retryMaxElapsed > 0 {
			elapsed := a.cfg.now().Sub(started)
			if elapsed+delay > a.cfg.retryMaxElapsed {
				break
			}
		}

		a.cfg.metrics.RetryScheduled(op, attempt+1, delay)
		a.debug("retrying operation", "op", op, "attempt", attempt+1, "delay", delay, "error", err)

		if werr := a.wait(ctx, delay); werr != nil {
			return werr
		}
	}

	return err
}

// wait sleeps for d, or returns early if the context ends or the
// authenticator is closed. The timer is stopped on every path so a long
// backoff on a cancelled request does not hold a runtime timer alive.
func (a *Client) wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-a.closed:
		return ErrClosed
	}
}
