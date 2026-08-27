package ldapauth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Conn is the slice of *ldap.Conn this package actually uses.
//
// The package talks to the directory only through this interface. That is
// what makes every layer above the wire testable without a server, and it
// keeps the package insulated from methods being added to go-ldap's own
// much larger Client interface. *ldap.Conn satisfies it as it stands.
type Conn interface {
	// Bind performs a simple bind. An empty password is an
	// unauthenticated bind and this package never issues one; see
	// ErrEmptyPassword.
	Bind(username, password string) error

	// Search performs a search operation.
	Search(request *ldap.SearchRequest) (*ldap.SearchResult, error)

	// SearchWithPaging performs a search operation with a paged results
	// control, for directories that cap the number of entries a single
	// search may return.
	SearchWithPaging(request *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)

	// WhoAmI issues the RFC 4532 "Who am I?" extended operation. The pool
	// uses it as a liveness probe.
	WhoAmI(controls []ldap.Control) (*ldap.WhoAmIResult, error)

	// SetTimeout bounds how long a single operation may take.
	SetTimeout(timeout time.Duration)

	// IsClosing reports whether the connection is shutting down.
	IsClosing() bool

	// Close releases the connection.
	Close() error
}

// Dialer opens connections to the directory.
//
// The package ships one, built from the TLS and timeout options, and uses
// it unless WithDialer replaces it. Replacing it is the supported way to
// reach a directory this package cannot dial on its own — a connection
// arriving over an SSH tunnel or a service mesh sidecar, say — and it is
// how the package's own tests drive failure paths without a server.
type Dialer interface {
	// DialContext opens a connection to url and returns it ready for a
	// bind: for an ldaps:// URL the TLS handshake has completed, and for
	// an ldap:// URL with StartTLS configured the upgrade has happened.
	//
	// Implementations must honour ctx for the duration of the dial and
	// must not retain it afterwards.
	DialContext(ctx context.Context, url string) (Conn, error)
}

// netDialer is the Dialer the package builds from its own options.
type netDialer struct {
	tlsConfig *tls.Config

	// startTLS asks for an RFC 4513 StartTLS upgrade on plaintext
	// connections. It is ignored for ldaps:// URLs, which are already
	// wrapped.
	startTLS bool

	dialTimeout time.Duration

	// opTimeout is applied to the connection before it is handed back, so
	// that a server that accepts a connection and then goes silent cannot
	// wedge a request past its deadline.
	opTimeout time.Duration
}

// DialContext implements Dialer.
//
// go-ldap's DialURL predates context and takes none, so the dial runs on
// its own goroutine and the context is honoured by racing it. When the
// context wins that race the goroutine is left to finish and close
// whatever it opened — abandoning a connection beats leaking a file
// descriptor, and the net.Dialer's own timeout bounds how long it can
// live, because until the TCP connection is up that timeout is the only
// thing happening.
//
// A StartTLS upgrade is a second phase, and it is deliberately not inside
// that goroutine. Two things there are unbounded by anything the dialer
// can set:
//
//   - Waiting for the server's StartTLS response. go-ldap bounds it by the
//     connection's own request timeout, which has to be set on the
//     connection before the request is sent.
//   - The TLS handshake that follows. go-ldap runs it with no deadline on
//     the socket at all, so a server that answers StartTLS and then stops
//     sending hangs until something closes the connection under it.
//
// net.Dialer.Timeout reaches neither: it bounds establishing the TCP
// connection and nothing after. So the connection is brought into this
// scope first, given a deadline, and only then upgraded — and if the
// context wins the upgrade race, this closes that known connection
// directly, which is both what unblocks the handshake and what stops a
// server that accepts connections and goes silent from costing a
// goroutine and a socket per attempt.
func (d *netDialer) DialContext(ctx context.Context, addr string) (Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ldapauth: dial %s: %w", addr, err)
	}

	timeout, err := d.budget(ctx)
	if err != nil {
		return nil, fmt.Errorf("ldapauth: dial %s: %w", addr, err)
	}

	conn, err := d.connect(ctx, addr, timeout)
	if err != nil {
		return nil, err
	}

	// Before anything is sent. This is what bounds the wait for the
	// StartTLS response, and it is the deadline every later operation
	// runs under.
	if d.opTimeout > 0 {
		conn.SetTimeout(d.opTimeout)
	}

	if d.startTLS && needsStartTLS(addr) {
		// The upgrade gets what is left of the dial budget rather than
		// the operation timeout: it is part of establishing the
		// connection, and a caller who allowed a second to connect did
		// not thereby allow a second more to negotiate TLS.
		remaining, err := d.budget(ctx)
		if err != nil {
			_ = conn.Close()

			return nil, fmt.Errorf("ldapauth: starttls %s: %w", addr, err)
		}

		if err := d.upgrade(ctx, conn, remaining); err != nil {
			_ = conn.Close()

			return nil, fmt.Errorf("ldapauth: starttls %s: %w", addr, err)
		}
	}

	return conn, nil
}

// budget returns how long this dial may take: the configured dial timeout,
// or what is left of the caller's deadline if that is sooner.
func (d *netDialer) budget(ctx context.Context) (time.Duration, error) {
	timeout := d.dialTimeout

	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}

	if timeout <= 0 {
		return 0, context.DeadlineExceeded
	}

	return timeout, nil
}

// connect opens the connection, racing go-ldap's context-free dial against
// the caller's context.
func (d *netDialer) connect(ctx context.Context, addr string, timeout time.Duration) (*ldap.Conn, error) {
	type dialResult struct {
		conn *ldap.Conn
		err  error
	}

	results := make(chan dialResult, 1)

	go func() {
		conn, err := ldap.DialURL(
			addr,
			ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
			ldap.DialWithTLSConfig(d.tlsConfig),
		)

		results <- dialResult{conn: conn, err: err}
	}()

	select {
	case <-ctx.Done():
		go func() {
			if r := <-results; r.conn != nil {
				_ = r.conn.Close()
			}
		}()

		return nil, fmt.Errorf("ldapauth: dial %s: %w", addr, ctx.Err())

	case r := <-results:
		if r.err != nil {
			return nil, fmt.Errorf("ldapauth: dial %s: %w", addr, r.err)
		}

		return r.conn, nil
	}
}

// upgrade performs the StartTLS exchange on an established connection,
// bounded by both timeout and the caller's context.
//
// Losing the race closes the connection rather than abandoning it. That is
// the only thing that unblocks a TLS handshake go-ldap is running with no
// deadline, and it is safe because the connection is not shared: nothing
// else can reach it until this function returns.
func (d *netDialer) upgrade(ctx context.Context, conn *ldap.Conn, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)

	go func() { done <- conn.StartTLS(d.tlsConfig) }()

	select {
	case err := <-done:
		return err

	case <-ctx.Done():
		// Closing it here is what ends the goroutine: the read it is
		// blocked in fails, StartTLS returns, and the send does not block
		// because the channel is buffered.
		_ = conn.Close()

		return ctx.Err()
	}
}

// needsStartTLS reports whether a StartTLS upgrade is meaningful for the
// URL. ldaps:// is already wrapped and ldapi:// is a unix socket whose
// security is filesystem permissions; upgrading either is at best a wasted
// round trip and at worst an error the server returns.
func needsStartTLS(addr string) bool {
	scheme, _, found := strings.Cut(addr, "://")
	if !found {
		return true
	}

	return strings.EqualFold(scheme, "ldap") || strings.EqualFold(scheme, "cldap")
}

// isPlaintextURL reports whether the URL would carry credentials in the
// clear absent a StartTLS upgrade. New uses it to enforce the TLS default.
func isPlaintextURL(addr string) bool {
	// A unix domain socket never leaves the host; its access control is
	// the filesystem's, and demanding TLS on top of it would rule out the
	// most secure deployment there is.
	if isUnixSocketURL(addr) {
		return false
	}

	u, err := url.Parse(addr)
	if err != nil {
		return true
	}

	return !strings.EqualFold(u.Scheme, "ldaps")
}

// isUnixSocketURL reports whether the URL is an ldapi:// socket path.
//
// It is checked by prefix rather than by parsing, because the socket path
// in an ldapi:// URL is percent-encoded into the authority component and
// net/url rejects the escapes there. go-ldap parses these itself for the
// same reason.
func isUnixSocketURL(addr string) bool {
	return strings.HasPrefix(strings.ToLower(addr), "ldapi://")
}

// validateURL checks that a configured URL is one the package can dial,
// before New returns rather than on the first authentication.
func validateURL(addr string) error {
	if isUnixSocketURL(addr) {
		if len(addr) == len("ldapi://") {
			return fmt.Errorf("%w: URL %q has no socket path", ErrInvalidOption, addr)
		}

		return nil
	}

	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("%w: URL %q: %w", ErrInvalidOption, addr, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "ldap", "ldaps", "cldap":
		if u.Host == "" {
			return fmt.Errorf("%w: URL %q has no host", ErrInvalidOption, addr)
		}
	case "":
		return fmt.Errorf(
			"%w: URL %q has no scheme; expected ldap://, ldaps://, or ldapi://",
			ErrInvalidOption, addr,
		)
	default:
		return fmt.Errorf(
			"%w: URL %q has unsupported scheme %q; expected ldap, ldaps, cldap, or ldapi",
			ErrInvalidOption, addr, u.Scheme,
		)
	}

	return nil
}
