// Command layered shows the shape a high-traffic deployment wants, and
// which parts of it this library is and is not.
//
//	go run ./examples/layered
//
//	application
//	  ↓  rate limiter        per client — not this library's job
//	  ↓  circuit breaker     per directory — not this library's job either
//	  ↓  ldap-authenticator  lockout protection, cache, retry, failover
//	  ↓  LDAP
//
// The two outer layers are decorators over ldapauth.Authenticator, which
// is why that interface exists. Neither belongs in the library: a rate
// limiter's policy is about your clients, and a circuit breaker's
// thresholds are about your traffic, and both are things every deployment
// already has an opinion and usually a library about.
//
// What the library does own is the layer underneath: refusing an account
// locally before its failures reach the directory's lockout counter,
// serving repeat logins from cache, retrying only what is worth retrying,
// and moving on from a replica that has stopped answering.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const peopleDN = "ou=people,dc=example,dc=com"

// ---- circuit breaker -----------------------------------------------------

// breaker stops asking a directory that has stopped answering.
//
// Without one, a directory that is completely down means every request
// pays the whole chain — dial timeout, failover to the next URL, another
// dial timeout, retries with backoff — before failing. That is seconds of
// held goroutines per request, and under load it is how a directory outage
// becomes an application outage.
//
// It wraps ldapauth.Authenticator and is therefore invisible to everything
// above it. Embedding the interface means a method added to it in a later
// 1.x release passes straight through rather than breaking this.
type breaker struct {
	ldapauth.Authenticator

	threshold int
	cooldown  time.Duration

	mu       sync.Mutex
	failures int
	openedAt time.Time
}

var errBreakerOpen = errors.New("circuit breaker: the directory is not answering")

func newBreaker(inner ldapauth.Authenticator, threshold int, cooldown time.Duration) *breaker {
	return &breaker{Authenticator: inner, threshold: threshold, cooldown: cooldown}
}

func (b *breaker) Authenticate(ctx context.Context, username, password string) (ldapauth.Identity, error) {
	if !b.allow() {
		return nil, errBreakerOpen
	}

	identity, err := b.Authenticator.Authenticate(ctx, username, password)

	// A rejected credential is a working directory. Only failures that
	// say the directory is unwell count, or the first user to mistype
	// their password would open the breaker for everybody.
	switch {
	case err == nil, errors.Is(err, ldapauth.ErrInvalidCredentials):
		b.succeed()
	default:
		b.fail()
	}

	return identity, err
}

func (b *breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.openedAt.IsZero() {
		return true
	}

	if time.Since(b.openedAt) < b.cooldown {
		return false
	}

	// Half open: let one through and see.
	b.openedAt = time.Time{}
	b.failures = b.threshold - 1

	return true
}

func (b *breaker) succeed() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures = 0
	b.openedAt = time.Time{}
}

func (b *breaker) fail() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures++

	if b.failures >= b.threshold {
		b.openedAt = time.Now()
	}
}

// ---- rate limiter --------------------------------------------------------

// limiter caps how often one client may attempt a login.
//
// This is the layer the library explicitly does not provide, and the
// reason is that its policy is about your clients rather than about your
// directory: per IP, per session, per API key, with your own bucket sizes
// and your own idea of what to do when it trips. The one below it —
// ldapauth.WithLockoutProtection — counts failures per *account*, which is
// a different question with a different answer.
type limiter struct {
	ldapauth.Authenticator

	perMinute int

	mu     sync.Mutex
	counts map[string]int
	minute int64
}

var errRateLimited = errors.New("rate limiter: too many attempts")

func newLimiter(inner ldapauth.Authenticator, perMinute int) *limiter {
	return &limiter{Authenticator: inner, perMinute: perMinute, counts: map[string]int{}}
}

// AuthenticateFrom is the limiter's own entry point, because who the
// client is does not come from the credential — it comes from the
// request, which is above this layer.
func (l *limiter) AuthenticateFrom(
	ctx context.Context,
	client, username, password string,
) (ldapauth.Identity, error) {
	if !l.allow(client) {
		return nil, errRateLimited
	}

	return l.Authenticator.Authenticate(ctx, username, password)
}

func (l *limiter) allow(client string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if minute := time.Now().Unix() / 60; minute != l.minute {
		l.minute = minute
		l.counts = map[string]int{}
	}

	l.counts[client]++

	return l.counts[client] <= l.perMinute
}

// ---- the stack -----------------------------------------------------------

func main() {
	dir := directory()

	client, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),

		// The library's own layer: attempts that would count against the
		// directory's lockout policy stop here.
		ldapauth.WithLockoutProtection(3, 5*time.Minute, time.Minute),

		ldapauth.WithoutRetry(),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}

	defer func() { _ = client.Close() }()

	stack := newLimiter(newBreaker(client, 3, 30*time.Second), 5)

	ctx := context.Background()

	fmt.Println("a normal login:")
	report(stack.AuthenticateFrom(ctx, "10.0.0.1", "alice", "s3cret"))

	fmt.Println("\nfour wrong passwords — the account's own protection trips on the fourth:")
	for range 4 {
		report(stack.AuthenticateFrom(ctx, "10.0.0.2", "alice", "wrong"))
	}

	fmt.Println("\nand the rate limiter trips for that client regardless of the account:")
	for range 3 {
		report(stack.AuthenticateFrom(ctx, "10.0.0.2", "bob", "wrong"))
	}

	fmt.Println("\nwith the directory down, the breaker stops the chain being paid per request:")
	dir.SetDown("ldap://in-memory", true)

	for range 5 {
		report(stack.AuthenticateFrom(ctx, "10.0.0.3", "carol", "s3cret"))
	}
}

func report(identity ldapauth.Identity, err error) {
	switch {
	case err == nil:
		fmt.Println("  authenticated:", identity.GetDN())
	case errors.Is(err, errRateLimited):
		fmt.Println("  rate limited")
	case errors.Is(err, errBreakerOpen):
		fmt.Println("  breaker open — the directory was not asked")
	case errors.Is(err, ldapauth.ErrTooManyAttempts):
		fmt.Println("  account in a local cooldown — the directory was not asked")
	case errors.Is(err, ldapauth.ErrInvalidCredentials):
		fmt.Println("  rejected")
	default:
		fmt.Println("  failed:", err)
	}
}

func directory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User("uid=alice,"+peopleDN, "s3cret").
			With("uid", "alice").With("objectClass", "inetOrgPerson"),
		ldaptest.User("uid=carol,"+peopleDN, "s3cret").
			With("uid", "carol").With("objectClass", "inetOrgPerson"),
	)
}
