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
// context wins, the goroutine is left to finish and close whatever it
// opened: abandoning a connection is preferable to leaking a file
// descriptor, and the net.Dialer's own timeout bounds how long that
// goroutine can live.
func (d *netDialer) DialContext(ctx context.Context, addr string) (Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ldapauth: dial %s: %w", addr, err)
	}

	type dialResult struct {
		conn *ldap.Conn
		err  error
	}

	timeout := d.dialTimeout

	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("ldapauth: dial %s: %w", addr, context.DeadlineExceeded)
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

		conn := r.conn

		if d.startTLS && needsStartTLS(addr) {
			if err := conn.StartTLS(d.tlsConfig); err != nil {
				_ = conn.Close()

				return nil, fmt.Errorf("ldapauth: starttls %s: %w", addr, err)
			}
		}

		if d.opTimeout > 0 {
			conn.SetTimeout(d.opTimeout)
		}

		return conn, nil
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
