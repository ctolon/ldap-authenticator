// Package integration exercises the library against a real LDAP server.
//
// Every test here skips unless a directory URL is given, with -ldap-url or
// the LDAPAUTH_TEST_URL environment variable, so that `go test ./...`
// stays fast and green on a laptop with nothing running. `make
// integration` brings up the container in compose.yml, seeds ldifs/, and
// runs this package with the flag set.
//
// What it covers is what an in-memory fake cannot answer: that a real
// directory accepts the filters and DNs this library builds, that its
// result codes classify the way the retry logic assumes, and — the one
// that matters most — that a bind with an empty password really does
// succeed against a conforming server.
package integration

import (
	"context"
	"errors"
	"flag"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

const (
	baseDN    = "dc=example,dc=com"
	peopleDN  = "ou=people," + baseDN
	groupsDN  = "ou=groups," + baseDN
	aliceDN   = "uid=alice," + peopleDN
	awkwardDN = "uid=awkward," + peopleDN
	serviceDN = "cn=readonly," + baseDN

	alicePassword   = "alice-password"
	bobPassword     = "bob-password"
	servicePassword = "service-password"
)

var ldapURL = flag.String("ldap-url", os.Getenv("LDAPAUTH_TEST_URL"),
	"URL of a directory seeded with ldifs/; the suite skips when empty")

// requireLDAP skips the test unless a directory was given.
func requireLDAP(t *testing.T) string {
	t.Helper()

	if *ldapURL == "" {
		t.Skip("no -ldap-url and no LDAPAUTH_TEST_URL; run `make integration`")
	}

	return *ldapURL
}

func newAuth(t *testing.T, opts ...ldapauth.Option) *ldapauth.Client {
	t.Helper()

	base := []ldapauth.Option{
		ldapauth.WithURL(requireLDAP(t)),

		// The container speaks plaintext; see compose.yml for why.
		ldapauth.WithInsecureNoTLS(),
		ldapauth.WithDialTimeout(5 * time.Second),
	}

	auth, err := ldapauth.New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() { _ = auth.Close() })

	return auth
}

func serviceAuth(t *testing.T, opts ...ldapauth.Option) *ldapauth.Client {
	t.Helper()

	base := []ldapauth.Option{
		ldapauth.WithServiceAccount(serviceDN, servicePassword),
		ldapauth.WithUserSearch(peopleDN, "(&(objectClass=inetOrgPerson)(uid={{username}}))"),
	}

	return newAuth(t, append(base, opts...)...)
}

func ctx(t *testing.T) context.Context {
	t.Helper()

	c, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)

	return c
}

func TestDirectBind(t *testing.T) {
	auth := newAuth(t, ldapauth.WithDirectBind("uid={{username}},"+peopleDN))

	p, err := auth.Authenticate(ctx(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if !strings.EqualFold(p.GetDN(), aliceDN) {
		t.Errorf("DN = %q, want %q", p.GetDN(), aliceDN)
	}

	if _, err := auth.Authenticate(ctx(t), "alice", "wrong"); !errors.Is(err, ldapauth.ErrInvalidCredentials) {
		t.Errorf("wrong password: err = %v, want ErrInvalidCredentials", err)
	}
}

func TestSearchThenBind(t *testing.T) {
	auth := serviceAuth(t,
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithDisplayNameAttribute("cn"),
	)

	p, err := auth.Authenticate(ctx(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if p.GetEmail() != "alice@example.com" {
		t.Errorf("Email = %q, want alice@example.com", p.GetEmail())
	}

	if p.GetDisplayName() != "Alice Example" {
		t.Errorf("DisplayName = %q, want %q", p.GetDisplayName(), "Alice Example")
	}
}

func TestARealServerAcceptsAnEmptyPasswordBind(t *testing.T) {
	url := requireLDAP(t)

	// This is the hazard, demonstrated rather than asserted from a
	// specification: a simple bind carrying no password is an
	// unauthenticated bind, and the server answers it with success. If
	// this test ever starts failing, it is because the server was
	// configured to disallow it — not because the hazard went away.
	conn, err := ldap.DialURL(url)
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}

	defer func() { _ = conn.Close() }()

	switch err := conn.Bind(aliceDN, ""); {
	case err == nil:
		t.Log("the directory accepted a bind with an empty password, as RFC 4511 requires")
	case ldap.IsErrorWithCode(err, ldap.ErrorEmptyPassword):
		t.Log("go-ldap refused to send an empty password before the server saw it")
	default:
		t.Logf("the directory refused an empty-password bind: %v", err)
	}

	// Whatever the server does, this library never asks.
	auth := newAuth(t, ldapauth.WithDirectBind("uid={{username}},"+peopleDN))

	if _, err := auth.Authenticate(ctx(t), "alice", ""); !errors.Is(err, ldapauth.ErrEmptyPassword) {
		t.Fatalf("err = %v, want ErrEmptyPassword", err)
	}
}

func TestFilterInjectionAgainstARealServer(t *testing.T) {
	auth := serviceAuth(t)

	for _, username := range []string{"*", "*)(uid=*", "alice)(|(uid=*", `alice\`} {
		_, err := auth.Authenticate(ctx(t), username, alicePassword)
		if !errors.Is(err, ldapauth.ErrInvalidCredentials) {
			t.Errorf("username %q: err = %v, want ErrInvalidCredentials", username, err)
		}
	}
}

func TestDNWithACommaRoundTrips(t *testing.T) {
	// The fixture holds an entry whose CN contains a comma, so that the
	// DN escaping is exercised against a server's own parser.
	auth := newAuth(t, ldapauth.WithDirectBind("uid={{username}},"+peopleDN))

	p, err := auth.Authenticate(ctx(t), "awkward", "awkward-password")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if !strings.EqualFold(p.GetDN(), awkwardDN) {
		t.Errorf("DN = %q, want %q", p.GetDN(), awkwardDN)
	}
}

func TestGroupSearch(t *testing.T) {
	auth := serviceAuth(t,
		ldapauth.WithGroupSearch(groupsDN, "(&(objectClass=groupOfNames)(member={{user_dn}}))"),
	)

	p, err := auth.Authenticate(ctx(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if !p.InGroup("developers") {
		t.Errorf("groups = %v, want developers", p.GetGroups())
	}

	if p.InGroup("staff") {
		t.Errorf("groups = %v, want staff excluded without nesting", p.GetGroups())
	}
}

func TestNestedGroupSearch(t *testing.T) {
	auth := serviceAuth(t,
		ldapauth.WithGroupSearch(groupsDN, "(&(objectClass=groupOfNames)(member={{user_dn}}))"),
		ldapauth.WithNestedGroups(),
	)

	p, err := auth.Authenticate(ctx(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if !p.InGroup("developers") || !p.InGroup("staff") {
		t.Errorf("groups = %v, want both developers and staff", p.GetGroups())
	}
}

func TestLookupNeedsNoPassword(t *testing.T) {
	auth := serviceAuth(t, ldapauth.WithEmailAttribute("mail"))

	p, err := auth.Lookup(ctx(t), "bob")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if p.GetEmail() != "bob@example.com" {
		t.Errorf("Email = %q, want bob@example.com", p.GetEmail())
	}

	if _, err := auth.Lookup(ctx(t), "nobody"); !errors.Is(err, ldapauth.ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

func TestHealthCheck(t *testing.T) {
	auth := serviceAuth(t)

	if err := auth.HealthCheck(ctx(t)); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

func TestFailoverPastADeadServer(t *testing.T) {
	url := requireLDAP(t)

	auth, err := ldapauth.New(
		// A port nothing is listening on, ahead of the real one.
		ldapauth.WithURLs("ldap://127.0.0.1:1", url),
		ldapauth.WithInsecureNoTLS(),
		ldapauth.WithDialTimeout(2*time.Second),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	defer func() { _ = auth.Close() }()

	if _, err := auth.Authenticate(ctx(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if stats := auth.Stats(ctx(t)); stats.HealthyServers != 1 {
		t.Errorf("HealthyServers = %d, want 1: the dead server should be in its cooldown", stats.HealthyServers)
	}
}

func TestConcurrentLoginsShareThePool(t *testing.T) {
	auth := serviceAuth(t, ldapauth.WithPoolSize(4), ldapauth.WithPoolMinIdle(2))

	var wg sync.WaitGroup

	errs := make(chan error, 32)

	for i := range 32 {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			username, password := "alice", alicePassword
			if i%2 == 1 {
				username, password = "bob", bobPassword
			}

			if _, err := auth.Authenticate(ctx(t), username, password); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	if stats := auth.Stats(ctx(t)); stats.PoolInUse != 0 {
		t.Errorf("PoolInUse = %d after every login finished, want 0", stats.PoolInUse)
	}
}

func TestPoolSurvivesAServerRestart(t *testing.T) {
	// Not a restart we can cause from here, but the same shape: a
	// connection that has been retired mid-life must be replaced rather
	// than reused.
	auth := serviceAuth(t,
		ldapauth.WithPoolMaxLifetime(time.Millisecond),
		ldapauth.WithPoolHealthCheck(true),
	)

	for range 3 {
		if _, err := auth.Authenticate(ctx(t), "alice", alicePassword); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}
}
