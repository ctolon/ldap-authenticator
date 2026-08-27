package ldapauth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// The sentinel errors the package returns. Callers should test with
// errors.Is rather than comparing strings; every error the package returns
// wraps its cause with %w, so the chain stays intact.
var (
	// ErrInvalidOption is returned by New when an option carries a value
	// that cannot be used, such as a negative timeout or a bind template
	// with no username placeholder. Options are validated at construction
	// rather than normalised silently, so a misconfiguration fails at
	// startup instead of on the first login attempt at 3am.
	ErrInvalidOption = errors.New("ldapauth: invalid option")

	// ErrClosed is returned by every method after Close.
	ErrClosed = errors.New("ldapauth: authenticator closed")

	// ErrEmptyUsername is returned before any network call when the
	// username is empty or is only whitespace.
	ErrEmptyUsername = errors.New("ldapauth: empty username")

	// ErrEmptyPassword is returned before any network call when the
	// password is empty.
	//
	// This is not a convenience check. RFC 4511 makes a simple bind
	// carrying a zero-length password an *unauthenticated* bind, which a
	// conforming server answers with success — so a directory that would
	// reject the wrong password accepts no password at all.
	//
	// go-ldap guards against this too, and has since v3.4: its Bind
	// refuses an empty password rather than sending one. This package
	// refuses earlier and more usefully. Earlier, because the check
	// happens before a connection is opened, so a login form being
	// hammered with empty passwords costs no handshakes. More usefully,
	// because the caller gets a sentinel to branch on rather than a
	// protocol error to parse — an empty password is a 400, not a 401.
	// And because two layers of guard against the one mistake that turns
	// an authenticator into a door is the right number.
	ErrEmptyPassword = errors.New("ldapauth: empty password")

	// ErrInvalidUsername is returned when the username contains a NUL or
	// another control character, or exceeds the configured maximum length.
	// Such a username cannot name a real directory entry; it can only be an
	// attempt to reach something else.
	ErrInvalidUsername = errors.New("ldapauth: invalid username")

	// ErrInvalidPassword is returned when the password exceeds the
	// configured maximum length. It is not "the password was wrong" —
	// that is ErrInvalidCredentials — but "this cannot be a password",
	// decided before anything reaches the wire.
	ErrInvalidPassword = errors.New("ldapauth: invalid password")

	// ErrInvalidCredentials reports that the directory rejected the bind.
	// It is returned both when the user does not exist and when the
	// password is wrong: the two are deliberately indistinguishable to the
	// caller so that an HTTP handler built on this package cannot leak an
	// account-enumeration oracle by accident. Set a logger if you need to
	// tell them apart in an operator-facing log.
	ErrInvalidCredentials = errors.New("ldapauth: invalid credentials")

	// ErrUserNotFound is returned by Lookup when the search matched no
	// entry. Authenticate never returns it; see ErrInvalidCredentials.
	ErrUserNotFound = errors.New("ldapauth: user not found")

	// ErrAmbiguousUser is returned when a user search matched more than one
	// entry. Binding as "whichever one came back first" would make the
	// identity that ends up authenticated depend on server-side ordering,
	// so the package refuses instead.
	ErrAmbiguousUser = errors.New("ldapauth: user search matched more than one entry")

	// ErrNoServerAvailable is returned when every configured URL failed to
	// dial, or when every URL is inside its failure cooldown.
	ErrNoServerAvailable = errors.New("ldapauth: no LDAP server available")

	// ErrPoolExhausted is returned when the connection pool is full and the
	// caller's context expired before a connection came free. It is a
	// backpressure signal, not a directory failure: the usual answer is a
	// larger pool or a shorter per-request deadline.
	ErrPoolExhausted = errors.New("ldapauth: connection pool exhausted")

	// ErrTLSRequired is returned by New when a plaintext ldap:// URL is
	// configured without StartTLS and without the explicit opt-out. See
	// WithInsecureNoTLS.
	ErrTLSRequired = errors.New("ldapauth: TLS required")

	// ErrNoSuchGroupAttribute is returned when the configured group
	// membership attribute is missing from an entry and strict group
	// resolution is enabled.
	ErrNoSuchGroupAttribute = errors.New("ldapauth: group membership attribute not present")

	// ErrReferral reports a search that came back with referrals and no
	// entries: the directory is saying the answer lives in another
	// partition, which on a multi-domain Active Directory forest usually
	// means the base DN names the wrong one. It is only returned under
	// ReferralFail; see WithReferralPolicy.
	ErrReferral = errors.New("ldapauth: the directory referred the search elsewhere")

	// ErrTooManyAttempts reports a username this process has refused too
	// often too recently, under WithLockoutProtection. The directory was
	// not asked, which is the point: the attempt that would have been
	// made is the attempt that would have counted against the directory's
	// own lockout policy.
	ErrTooManyAttempts = errors.New("ldapauth: too many recent failures for this account")
)

// AuthError carries the operational detail behind a failed operation:
// which step failed, which server it was talking to, and the LDAP result
// code the directory returned. It always wraps a sentinel, so
//
//	errors.Is(err, ldapauth.ErrInvalidCredentials)
//
// keeps working whether or not the caller cares about the detail.
//
// The password is never a field of this type, and Username is only
// populated when username redaction is off.
type AuthError struct {
	// Op names the step that failed, such as "bind" or "search".
	Op string

	// URL is the server the operation was talking to, if the failure
	// happened after a connection was established. Empty otherwise.
	URL string

	// Username is the account the operation concerned, or "[redacted]"
	// when WithUsernameRedaction is on.
	Username string

	// ResultCode is the LDAP result code the directory returned, or zero
	// when the failure never reached the protocol layer (a dial failure,
	// say). Compare it against the ldap.LDAPResult* constants.
	ResultCode uint16

	// Reason is why the directory refused, when the directory said. It is
	// ReasonUnspecified otherwise, which is most of the time on most
	// directories.
	//
	// Log it, count it, audit it. Do not answer with it: the whole point
	// of Authenticate returning one error for every refusal is that a
	// caller cannot accidentally build an enumeration oracle, and putting
	// the reason in a response body rebuilds one.
	Reason RejectionReason

	// Referrals are the referral URLs a search came back with, when it
	// came back with referrals and nothing else. They are the directory
	// saying "what you are looking for is not in this partition, try
	// over there"; see WithReferralPolicy.
	Referrals []string

	// Err is the wrapped cause: always a sentinel from this package,
	// possibly with the underlying *ldap.Error below it.
	Err error
}

// Error renders the failure as "ldapauth: <op> for <user> on <url>:
// <result code>: <cause>", omitting whichever parts are not known.
func (e *AuthError) Error() string {
	var b strings.Builder

	b.WriteString("ldapauth: ")
	b.WriteString(e.Op)

	if e.Username != "" {
		b.WriteString(" for ")
		b.WriteString(e.Username)
	}

	if e.URL != "" {
		b.WriteString(" on ")
		b.WriteString(e.URL)
	}

	if e.ResultCode != 0 {
		fmt.Fprintf(&b, ": %s (%d)", ldap.LDAPResultCodeMap[e.ResultCode], e.ResultCode)
	}

	if e.Reason != ReasonUnspecified {
		b.WriteString(" [")
		b.WriteString(e.Reason.String())
		b.WriteString("]")
	}

	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}

	return b.String()
}

// Unwrap returns the wrapped cause so that errors.Is and errors.As reach
// the sentinel and any *ldap.Error beneath it.
func (e *AuthError) Unwrap() error { return e.Err }

// enrich fills in what an outer layer knows and an inner one did not, and
// returns the same error rather than a new one wrapping it.
//
// Wrapping an *AuthError in another *AuthError loses information in a way
// that is easy to miss: errors.As stops at the outermost match, so a
// Referrals or a Reason set deep down becomes unreachable while the error
// still reads correctly. Enriching in place keeps one of these per
// failure, which is also one per failure that a caller has to reason
// about.
func (e *AuthError) enrich(op, username string) *AuthError {
	if e.Op == "" {
		e.Op = op
	}

	if e.Username == "" {
		e.Username = username
	}

	return e
}

// asAuthError reports whether an error already carries an *AuthError.
func asAuthError(err error) (*AuthError, bool) {
	var authErr *AuthError

	ok := errors.As(err, &authErr)

	return authErr, ok
}

// resultCode digs the LDAP result code out of an error chain, returning
// zero when the failure never reached the protocol layer.
func resultCode(err error) uint16 {
	var lerr *ldap.Error
	if errors.As(err, &lerr) {
		return lerr.ResultCode
	}

	return 0
}
