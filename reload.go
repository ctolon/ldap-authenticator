package ldapauth

import (
	"context"
	"sync/atomic"
)

// A Reloadable is an [Authenticator] whose underlying [Client] can be
// replaced while it is in use.
//
// The service account password is read once, when the Client is built, and
// there is deliberately no way to change it underneath a running one — a
// field that can change while requests read it is a field that needs a
// lock, and the lock would be on the hot path of every login to serve a
// rotation that happens twice a year.
//
// The answer is to build a new Client and swap the pointer, which is what
// this is. It exists because everybody writes it, and because the part
// people get wrong is the ordering: the old Client must be closed *after*
// the swap, never before, or requests already choosing it find it closed.
//
//	reloadable := ldapauth.NewReloadable(client)
//
//	// ... later, when the secret manager says the password changed:
//	next, err := ldapauth.New(optionsWith(newPassword)...)
//	if err != nil {
//	    return err            // keep serving with the old one
//	}
//
//	previous := reloadable.Replace(next)
//	previous.Close()
//
// Closing the old Client does not interrupt requests already running on
// it; they finish against connections that are closed as they are
// released. What it does stop is new requests, and by the time Close is
// called there are none, because the swap already happened.
//
// A Reloadable is safe for concurrent use, and reading the current Client
// costs an atomic load — which is to say it costs nothing worth measuring.
type Reloadable struct {
	current atomic.Pointer[Client]
}

// Reloadable implements Authenticator. Asserted here rather than in a test
// so that it is checked by every build, including a consumer's.
var _ Authenticator = (*Reloadable)(nil)

// NewReloadable wraps a Client. It panics on a nil Client, because a
// Reloadable with nothing in it has no useful behaviour and would fail on
// the first request instead of at startup.
func NewReloadable(client *Client) *Reloadable {
	if client == nil {
		panic("ldapauth: NewReloadable was given a nil client")
	}

	r := &Reloadable{}
	r.current.Store(client)

	return r
}

// Replace swaps in a new Client and returns the one it replaced, for the
// caller to close.
//
// The previous Client is returned rather than closed here, because when to
// close it is the caller's decision: immediately is right for a password
// rotation, and after a grace period is right if something outside this
// package still holds a reference. It is never nil.
//
// Replace panics on a nil Client. Reloading is a thing that goes wrong —
// the secret manager was unreachable, the new password is not live yet —
// and the right answer to a failed reload is to keep serving with the
// Client you have, not to install nothing.
func (r *Reloadable) Replace(next *Client) (previous *Client) {
	if next == nil {
		panic("ldapauth: Replace was given a nil client")
	}

	return r.current.Swap(next)
}

// Current returns the Client in use, for the calls this interface does not
// cover.
func (r *Reloadable) Current() *Client { return r.current.Load() }

// Authenticate verifies a username and password against the current
// Client.
func (r *Reloadable) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	return r.current.Load().Authenticate(ctx, username, password)
}

// Lookup reads an identity from the current Client.
func (r *Reloadable) Lookup(ctx context.Context, username string) (Identity, error) {
	return r.current.Load().Lookup(ctx, username)
}

// HealthCheck probes the current Client's directory.
func (r *Reloadable) HealthCheck(ctx context.Context) error {
	return r.current.Load().HealthCheck(ctx)
}

// Stats reports the current Client's occupancy.
func (r *Reloadable) Stats(ctx context.Context) Stats {
	return r.current.Load().Stats(ctx)
}

// InvalidateUser drops an account's cached outcomes from the current
// Client.
func (r *Reloadable) InvalidateUser(ctx context.Context, username string) (int, error) {
	return r.current.Load().InvalidateUser(ctx, username)
}

// InvalidateAll empties the current Client's cache.
func (r *Reloadable) InvalidateAll(ctx context.Context) (int, error) {
	return r.current.Load().InvalidateAll(ctx)
}

// Close closes the current Client. It does not close any Client that was
// previously replaced: Replace handed those back, and closing them was the
// caller's to do.
func (r *Reloadable) Close() error {
	return r.current.Load().Close()
}
