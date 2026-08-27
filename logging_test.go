package ldapauth_test

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

// captureLogs collects everything the package logs, at debug level, so
// that a test can assert on what is in it — and, more usefully, on what is
// not.
type captureLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *captureLogs) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.buf.Write(p)
}

func (c *captureLogs) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.buf.String()
}

func (c *captureLogs) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(c, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// exercise runs enough of the package to touch every logging call site
// that a normal deployment reaches.
func exercise(t *testing.T, auth *ldapauth.Client, password string) {
	t.Helper()

	ctx := testContext(t)

	if _, err := auth.Authenticate(ctx, "alice", password); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if _, err := auth.Authenticate(ctx, "alice", password+"-wrong"); err == nil {
		t.Fatal("Authenticate succeeded with the wrong password")
	}

	if _, err := auth.Lookup(ctx, "alice"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if err := auth.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}

	if err := auth.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNoPasswordEverReachesALogRecord(t *testing.T) {
	t.Parallel()

	// The claim in SECURITY.md, tested rather than asserted. Both
	// passwords are distinctive strings, so a substring search over
	// everything the package logged is a complete check rather than a
	// hopeful one.
	const (
		userPassword    = "unmistakable-user-password-9f3a"
		servicePassword = "unmistakable-service-password-4c1d"
	)

	dir := newDirectory()
	dir.Add(passwordUser(aliceDN, userPassword), passwordUser(serviceDN, servicePassword))

	logs := &captureLogs{}

	auth := newAuthenticator(t, dir,
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(serviceDN, servicePassword),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithNestedGroups(),
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithLogger(logs.logger()),
	)

	exercise(t, auth, userPassword)

	written := logs.String()

	if written == "" {
		t.Fatal("nothing was logged; the test proves nothing")
	}

	for _, secret := range []string{userPassword, servicePassword} {
		if strings.Contains(written, secret) {
			t.Errorf("a password appears in the log output:\n%s", written)
		}
	}
}

func TestNoPasswordEverReachesAnError(t *testing.T) {
	t.Parallel()

	const password = "unmistakable-user-password-77b2"

	dir := newDirectory()
	dir.Add(passwordUser(aliceDN, password))

	auth := directAuth(t, dir)

	// Every error path a caller can reach, including the ones that carry
	// a wrapped protocol error up from go-ldap.
	//
	// The over-length case is here because it is the one a scanner points
	// at: its message is built from the submitted password, and CodeQL
	// reports the flow. What it actually interpolates is len(password)
	// and the configured bound, both integers — which is a thing to
	// assert rather than to argue about in a comment.
	attempts := []struct{ username, password string }{
		{"alice", password + "-wrong"},
		{"alice", ""},
		{"nobody", password},
		{"*)(uid=*", password},
		{"alice", strings.Repeat(password, 200)},
	}

	for _, attempt := range attempts {
		_, err := auth.Authenticate(testContext(t), attempt.username, attempt.password)
		if err == nil {
			continue
		}

		if strings.Contains(err.Error(), password) {
			t.Errorf("username %q: the error text carries the password: %v", attempt.username, err)
		}
	}
}

func TestUsernameRedactionReachesTheLog(t *testing.T) {
	t.Parallel()

	logs := &captureLogs{}

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithUsernameRedaction(),
		ldapauth.WithLogger(logs.logger()),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	written := logs.String()

	if !strings.Contains(written, "[redacted]") {
		t.Errorf("nothing was redacted:\n%s", written)
	}

	// The DN still appears, and that is deliberate: it is what an
	// operator needs in order to find the entry, and it is not the thing
	// redaction is protecting.
	if strings.Contains(written, "username=alice") {
		t.Errorf("the username survived redaction:\n%s", written)
	}
}

func TestTheDefaultLoggerWritesNothing(t *testing.T) {
	t.Parallel()

	// No logger configured must mean no output anywhere, not output to
	// the default handler. A library that logs to stderr uninvited is a
	// library that shows up in somebody else's incident.
	logs := &captureLogs{}

	previous := slog.Default()
	slog.SetDefault(logs.logger())

	t.Cleanup(func() { slog.SetDefault(previous) })

	auth := searchAuth(t, newDirectory())

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if written := logs.String(); written != "" {
		t.Errorf("the package logged without being given a logger:\n%s", written)
	}
}
