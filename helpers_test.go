package ldapauth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

// The fixture every test builds on: two users, a service account, and a
// group tree with one level of nesting.
//
//	cn=staff ──contains── cn=devs ──contains── alice
//	                                           bob
const (
	baseDN    = "dc=example,dc=com"
	peopleDN  = "ou=people,dc=example,dc=com"
	groupsDN  = "ou=groups,dc=example,dc=com"
	aliceDN   = "uid=alice," + peopleDN
	bobDN     = "uid=bob," + peopleDN
	serviceDN = "cn=svc," + baseDN
	devsDN    = "cn=devs," + groupsDN
	staffDN   = "cn=staff," + groupsDN

	alicePassword   = "alice-s3cret"
	bobPassword     = "bob-s3cret"
	servicePassword = "svc-s3cret"

	memoryURL = "ldap://memory"
)

// newDirectory builds the fixture. Each test gets its own, so that the
// recorded binds and searches belong to it alone and tests can run in
// parallel.
func newDirectory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User(aliceDN, alicePassword).
			With("uid", "alice").
			With("cn", "Alice Example").
			With("mail", "alice@example.com").
			With("objectClass", "inetOrgPerson").
			With("memberOf", devsDN),

		ldaptest.User(bobDN, bobPassword).
			With("uid", "bob").
			With("cn", "Bob Example").
			With("mail", "bob@example.com").
			With("objectClass", "inetOrgPerson"),

		ldaptest.User(serviceDN, servicePassword).With("cn", "svc"),

		ldaptest.Group(devsDN).
			With("cn", "devs").
			With("objectClass", "groupOfNames").
			With("member", aliceDN).
			With("memberOf", staffDN),

		ldaptest.Group(staffDN).
			With("cn", "staff").
			With("objectClass", "groupOfNames").
			With("member", devsDN),
	)
}

// newAuthenticator builds an authenticator against dir, with the given
// options appended to the ones every test needs. It registers Close.
func newAuthenticator(t *testing.T, dir *ldaptest.Directory, opts ...ldapauth.Option) *ldapauth.Client {
	t.Helper()

	base := []ldapauth.Option{
		ldapauth.WithURL(memoryURL),
		ldapauth.WithDialer(dir.Dialer()),
	}

	auth, err := ldapauth.New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() { _ = auth.Close() })

	return auth
}

// searchAuth is the search-then-bind fixture, which is what most tests
// want: it exercises the pool, the service bind, and the user search.
func searchAuth(t *testing.T, dir *ldaptest.Directory, opts ...ldapauth.Option) *ldapauth.Client {
	t.Helper()

	base := []ldapauth.Option{
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(serviceDN, servicePassword),
	}

	return newAuthenticator(t, dir, append(base, opts...)...)
}

// directAuth is the direct-bind fixture, with no service account at all.
func directAuth(t *testing.T, dir *ldaptest.Directory, opts ...ldapauth.Option) *ldapauth.Client {
	t.Helper()

	base := []ldapauth.Option{
		ldapauth.WithDirectBind("uid={{username}}," + peopleDN),
	}

	return newAuthenticator(t, dir, append(base, opts...)...)
}

// passwordUser builds a replacement entry for one of the fixture's users,
// so that a test can pick a password distinctive enough to search for.
func passwordUser(dn, password string) *ldaptest.Entry {
	return ldaptest.User(dn, password).
		With("uid", strings.TrimSuffix(strings.TrimPrefix(dn, "uid="), ","+peopleDN)).
		With("cn", "Fixture User").
		With("mail", "fixture@example.com").
		With("objectClass", "inetOrgPerson").
		With("memberOf", devsDN)
}

// testContext is a context that dies with the test.
func testContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	return ctx
}

// fakeClock is a manually advanced clock, so that expiry can be asserted
// rather than waited for. It is safe for concurrent use because the
// authenticator reads it from several goroutines.
type fakeClock struct {
	mu  chan struct{}
	now time.Time
}

func newClock() *fakeClock {
	c := &fakeClock{
		mu:  make(chan struct{}, 1),
		now: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
	}
	c.mu <- struct{}{}

	return c
}

func (c *fakeClock) Now() time.Time {
	<-c.mu
	defer func() { c.mu <- struct{}{} }()

	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	<-c.mu
	defer func() { c.mu <- struct{}{} }()

	c.now = c.now.Add(d)
}
