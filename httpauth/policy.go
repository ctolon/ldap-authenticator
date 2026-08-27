package httpauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

// ErrForbidden reports that the credentials were valid but the principal
// is not in the groups the policy requires. It is separate from
// [ldapauth.ErrInvalidCredentials] because the two deserve different
// answers: a 401 invites the client to try again with other credentials,
// and a 403 tells it not to bother.
var ErrForbidden = errors.New("httpauth: identity is not in a required group")

// DefaultRealm is the realm sent in the WWW-Authenticate header when none
// is configured.
const DefaultRealm = "Restricted"

// A Policy is the framework-independent half of HTTP authentication: it
// turns a username and password into a principal, applies the group
// requirement, and pads the response time. The middleware in this package
// and the adapters under contrib/ are thin wrappers around one.
//
// Build it once and share it; it is safe for concurrent use.
type Policy struct {
	realm string

	anyGroups []string

	allGroups []string

	minDuration time.Duration

	errorHandler func(http.ResponseWriter, *http.Request, error)

	skip func(*http.Request) bool

	// maxBody bounds how much of a login request body is read.
	maxBody int64
}

// An Option configures a Policy.
type Option func(*Policy) error

// NewPolicy resolves options into a Policy. The middleware constructors
// call it for you; call it directly when building an adapter for a
// framework this repository does not ship.
func NewPolicy(opts ...Option) (*Policy, error) {
	p := &Policy{
		realm:   DefaultRealm,
		maxBody: DefaultMaxBodyBytes,
	}

	for i, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("httpauth: option %d is nil", i)
		}

		if err := opt(p); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// DefaultMaxBodyBytes bounds the login request body. Credentials are
// small; a body larger than this is not a login.
const DefaultMaxBodyBytes = 64 << 10

// WithRealm sets the realm offered in the WWW-Authenticate header.
func WithRealm(realm string) Option {
	return func(p *Policy) error {
		if realm == "" {
			return errors.New("httpauth: WithRealm was given an empty realm")
		}

		// A realm is a quoted string in the header, and a quote or a
		// backslash inside it would let the value break out of the
		// quoting and forge a second challenge parameter.
		for i := 0; i < len(realm); i++ {
			if realm[i] == '"' || realm[i] == '\\' || realm[i] < 0x20 {
				return fmt.Errorf("httpauth: realm %q contains a character that cannot be quoted", realm)
			}
		}

		p.realm = realm

		return nil
	}
}

// RequireAnyGroup rejects a principal that is in none of the named groups.
// Calling it more than once appends. With no groups named, nothing is
// required.
//
// Group membership has to be configured on the authenticator as well —
// [ldapauth.WithMemberOfGroups] or [ldapauth.WithGroupSearch] — or the
// identity arrives with no groups and every requirement fails.
func RequireAnyGroup(groups ...string) Option {
	return func(p *Policy) error {
		p.anyGroups = append(p.anyGroups, groups...)

		return nil
	}
}

// RequireAllGroups rejects a principal that is not in every named group.
// Calling it more than once appends.
func RequireAllGroups(groups ...string) Option {
	return func(p *Policy) error {
		p.allGroups = append(p.allGroups, groups...)

		return nil
	}
}

// WithMinimumDuration pads every authentication to at least d, successes
// and failures alike.
//
// It blunts the timing difference between a username that exists and one
// that does not: a search that matches nothing returns sooner than a
// search that matches and then binds, and that difference is measurable
// over a network. Padding is not a constant-time guarantee — nothing built
// on a directory round trip can be — but it moves the signal below the
// noise of the network in front of it.
//
// Pick a value above your directory's typical login latency: 100ms is a
// reasonable starting point. Zero, the default, does not pad.
func WithMinimumDuration(d time.Duration) Option {
	return func(p *Policy) error {
		if d < 0 {
			return fmt.Errorf("httpauth: minimum duration %s is negative", d)
		}

		p.minDuration = d

		return nil
	}
}

// WithErrorHandler replaces what a rejection looks like on the wire. The
// default sends 401 with a WWW-Authenticate challenge for bad credentials,
// 403 for a failed group requirement, and 503 for anything else, each with
// an empty body.
//
// A handler must write a response. It must not write the principal, and it
// should not write the error: the error text can name the account, and
// under some directories the reason it was refused.
func WithErrorHandler(h func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(p *Policy) error {
		if h == nil {
			return errors.New("httpauth: WithErrorHandler was given a nil handler")
		}

		p.errorHandler = h

		return nil
	}
}

// WithSkip leaves requests alone when the predicate returns true, for
// health endpoints and anything else mounted behind the same middleware.
func WithSkip(skip func(*http.Request) bool) Option {
	return func(p *Policy) error {
		if skip == nil {
			return errors.New("httpauth: WithSkip was given a nil predicate")
		}

		p.skip = skip

		return nil
	}
}

// WithMaxBodyBytes bounds how much of a login request body is read. The
// default is DefaultMaxBodyBytes.
func WithMaxBodyBytes(n int64) Option {
	return func(p *Policy) error {
		if n < 1 {
			return fmt.Errorf("httpauth: max body %d is below 1", n)
		}

		p.maxBody = n

		return nil
	}
}

// Realm returns the configured realm.
func (p *Policy) Realm() string { return p.realm }

// MaxBodyBytes returns the configured login body limit.
//
// It is exported because the framework adapters have to apply it
// themselves, and a limit only the net/http middleware honoured would make
// "one policy, shared by every adapter" untrue in the one place it is
// load-bearing.
func (p *Policy) MaxBodyBytes() int64 { return p.maxBody }

// ShouldSkip reports whether the policy leaves this request alone.
//
// Exported for the same reason as MaxBodyBytes. It reports false when no
// skip predicate is configured, and for a request an adapter cannot
// represent as an *http.Request — the Fiber one, which is why that
// adapter's documentation says so.
func (p *Policy) ShouldSkip(r *http.Request) bool {
	return r != nil && p.skip != nil && p.skip(r)
}

// Challenge is the value of the WWW-Authenticate header this policy sends.
func (p *Policy) Challenge() string {
	return `Basic realm="` + p.realm + `", charset="UTF-8"`
}

// Authenticate verifies credentials and applies the group requirement,
// padding the call to the configured minimum duration whatever the
// outcome.
//
// It is what every middleware in this package and under contrib/ calls,
// and it is exported so that an adapter for another framework is a matter
// of moving values in and out of that framework's context.
func (p *Policy) Authenticate(
	ctx context.Context,
	auth ldapauth.Authenticator,
	username, password string,
) (ldapauth.Identity, error) {
	started := time.Now()

	identity, err := auth.Authenticate(ctx, username, password)
	if err == nil {
		err = p.authorise(identity)
	}

	p.pad(ctx, started)

	if err != nil {
		return nil, err
	}

	return identity, nil
}

// authorise applies the group requirement.
func (p *Policy) authorise(identity ldapauth.Identity) error {
	if len(p.anyGroups) > 0 && !identity.InAnyGroup(p.anyGroups...) {
		return ErrForbidden
	}

	if len(p.allGroups) > 0 && !identity.InAllGroups(p.allGroups...) {
		return ErrForbidden
	}

	return nil
}

// pad waits out the remainder of the minimum duration. It gives up early
// if the client has gone, because padding a response nobody will read is
// just holding a goroutine.
func (p *Policy) pad(ctx context.Context, started time.Time) {
	if p.minDuration <= 0 {
		return
	}

	remaining := p.minDuration - time.Since(started)
	if remaining <= 0 {
		return
	}

	timer := time.NewTimer(remaining)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// Reject writes the response for a failed authentication.
func (p *Policy) Reject(w http.ResponseWriter, r *http.Request, err error) {
	if p.errorHandler != nil {
		p.errorHandler(w, r, err)

		return
	}

	switch Status(err) {
	case http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", p.Challenge())
		w.WriteHeader(http.StatusUnauthorized)

	case http.StatusForbidden:
		w.WriteHeader(http.StatusForbidden)

	case http.StatusBadRequest:
		w.WriteHeader(http.StatusBadRequest)

	default:
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

// Status maps an authentication error to the status code that answers it.
//
// It is exported because an adapter for another framework needs the same
// mapping, and because an application writing its own error handler should
// not have to reconstruct it from the sentinels.
//
//	401  the credentials were wrong, or absent
//	403  the credentials were right and the groups were not
//	400  the request was not a login: no username, no password
//	503  the directory could not answer
func Status(err error) int {
	switch {
	case err == nil:
		return http.StatusOK

	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden

	case errors.Is(err, ldapauth.ErrInvalidCredentials),
		errors.Is(err, ErrNoCredentials):
		return http.StatusUnauthorized

	case errors.Is(err, ldapauth.ErrEmptyUsername),
		errors.Is(err, ldapauth.ErrEmptyPassword),
		errors.Is(err, ldapauth.ErrInvalidUsername),
		errors.Is(err, ldapauth.ErrInvalidPassword),
		errors.Is(err, ErrMalformedRequest):
		return http.StatusBadRequest

	default:
		return http.StatusServiceUnavailable
	}
}
