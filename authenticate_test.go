package ldapauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

func TestDirectBindAuthenticates(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := directAuth(t, dir)

	p, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if p.GetDN() != aliceDN {
		t.Errorf("DN = %q, want %q", p.GetDN(), aliceDN)
	}

	if p.GetUsername() != "alice" {
		t.Errorf("Username = %q, want the username as supplied", p.GetUsername())
	}

	binds := dir.Binds()
	if len(binds) != 1 {
		t.Fatalf("binds = %d, want 1 for a direct bind with nothing to look up", len(binds))
	}

	if binds[0].DN != aliceDN {
		t.Errorf("bound as %q, want %q", binds[0].DN, aliceDN)
	}
}

func TestSearchThenBindAuthenticates(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir)

	p, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if p.GetDN() != aliceDN {
		t.Errorf("DN = %q, want %q", p.GetDN(), aliceDN)
	}

	binds := dir.Binds()
	if len(binds) != 2 {
		t.Fatalf("binds = %d, want 2: the service account and the user", len(binds))
	}

	if binds[0].DN != serviceDN || binds[1].DN != aliceDN {
		t.Errorf("bind order = %q then %q, want the service account then the user", binds[0].DN, binds[1].DN)
	}
}

func TestUserBindNeverSharesTheServiceConnection(t *testing.T) {
	t.Parallel()

	// The invariant: the connection the user is bound on is not the
	// connection the service account searches on. If it were, the next
	// request to take that connection out of the pool would be searching
	// as the user who happened to log in last.
	dir := newDirectory()
	auth := searchAuth(t, dir)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	binds := dir.Binds()
	if len(binds) != 2 {
		t.Fatalf("binds = %d, want 2", len(binds))
	}

	if binds[0].URL == binds[1].URL && binds[0].DN == binds[1].DN {
		t.Fatal("the service bind and the user bind look like the same connection")
	}

	opened, _ := dir.Conns()
	if opened < 2 {
		t.Errorf("connections opened = %d, want at least 2: one pooled, one for the user bind", opened)
	}
}

func TestWrongPasswordIsInvalidCredentials(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory())

	_, err := auth.Authenticate(testContext(t), "alice", "not-the-password")
	if !errors.Is(err, ldapauth.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestUnknownUserIsIndistinguishableFromAWrongPassword(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory())

	_, err1 := auth.Authenticate(testContext(t), "nobody", "whatever")
	_, err2 := auth.Authenticate(testContext(t), "alice", "whatever")

	if !errors.Is(err1, ldapauth.ErrInvalidCredentials) {
		t.Fatalf("unknown user: err = %v, want ErrInvalidCredentials", err1)
	}

	if !errors.Is(err2, ldapauth.ErrInvalidCredentials) {
		t.Fatalf("wrong password: err = %v, want ErrInvalidCredentials", err2)
	}

	if errors.Is(err1, ldapauth.ErrUserNotFound) {
		t.Error("Authenticate reported ErrUserNotFound, which is an account enumeration oracle")
	}
}

func TestEmptyPasswordIsRejectedBeforeAnyBind(t *testing.T) {
	t.Parallel()

	// The hazard: RFC 4511 makes a simple bind with a zero-length password
	// an unauthenticated bind, which a conforming server answers with
	// success. The in-memory directory models that faithfully, so this
	// test fails loudly if the check is ever removed.
	dir := newDirectory()
	auth := directAuth(t, dir)

	_, err := auth.Authenticate(testContext(t), "alice", "")
	if !errors.Is(err, ldapauth.ErrEmptyPassword) {
		t.Fatalf("err = %v, want ErrEmptyPassword", err)
	}

	if binds := dir.Binds(); len(binds) != 0 {
		t.Fatalf("binds = %d, want 0: the empty password must never reach the directory", len(binds))
	}
}

func TestEmptyPasswordIsRejectedUnderSearchThenBind(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir)

	_, err := auth.Authenticate(testContext(t), "alice", "")
	if !errors.Is(err, ldapauth.ErrEmptyPassword) {
		t.Fatalf("err = %v, want ErrEmptyPassword", err)
	}

	for _, bind := range dir.Binds() {
		if bind.Password == "" {
			t.Fatalf("a bind as %q was issued with an empty password", bind.DN)
		}
	}
}

func TestEmptyUsernameIsRejected(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir)

	for _, username := range []string{"", "   ", "\t\n"} {
		if _, err := auth.Authenticate(testContext(t), username, "x"); !errors.Is(err, ldapauth.ErrEmptyUsername) {
			t.Errorf("username %q: err = %v, want ErrEmptyUsername", username, err)
		}
	}

	if searches := dir.Searches(); len(searches) != 0 {
		t.Errorf("searches = %d, want 0: an empty username costs no round trip", len(searches))
	}
}

func TestControlCharactersInUsernameAreRejected(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir)

	for _, username := range []string{"ali\x00ce", "alice\n", "ali\rce", "\x1balice"} {
		_, err := auth.Authenticate(testContext(t), username, "x")
		if !errors.Is(err, ldapauth.ErrInvalidUsername) {
			t.Errorf("username %q: err = %v, want ErrInvalidUsername", username, err)
		}
	}

	if searches := dir.Searches(); len(searches) != 0 {
		t.Errorf("searches = %d, want 0", len(searches))
	}
}

func TestOverlongUsernameIsRejected(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(), ldapauth.WithUsernameMaxLength(8))

	_, err := auth.Authenticate(testContext(t), strings.Repeat("a", 9), "x")
	if !errors.Is(err, ldapauth.ErrInvalidUsername) {
		t.Fatalf("err = %v, want ErrInvalidUsername", err)
	}
}

func TestFilterInjectionIsEscaped(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir)

	// The classic: a filter of (uid=*)(|(uid=* would match every entry,
	// and a package that concatenated would then bind as whichever one the
	// directory returned first.
	hostile := []string{
		"*",
		"*)(uid=*",
		"alice)(|(uid=*",
		`alice\`,
		"alice\x2a",
	}

	for _, username := range hostile {
		_, err := auth.Authenticate(testContext(t), username, "x")
		if !errors.Is(err, ldapauth.ErrInvalidCredentials) {
			t.Errorf("username %q: err = %v, want ErrInvalidCredentials", username, err)
		}
	}

	for _, filter := range dir.Filters() {
		if strings.Count(filter, "(") != 1 || strings.Count(filter, ")") != 1 {
			t.Errorf("filter %q gained structure from the username", filter)
		}
	}
}

func TestDNInjectionIsEscaped(t *testing.T) {
	t.Parallel()

	// alice-with-a-comma must not become a DN in the admin subtree.
	dir := newDirectory().Add(
		ldaptest.User("uid=intruder,ou=admins,"+baseDN, "guessed").With("uid", "intruder"),
	)

	auth := directAuth(t, dir)

	_, err := auth.Authenticate(testContext(t), "intruder,ou=admins,dc=example,dc=com", "guessed")
	if !errors.Is(err, ldapauth.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}

	binds := dir.Binds()
	if len(binds) != 1 {
		t.Fatalf("binds = %d, want 1", len(binds))
	}

	if !strings.Contains(binds[0].DN, `\,`) {
		t.Errorf("bound as %q, want the comma escaped", binds[0].DN)
	}
}

func TestAmbiguousUserIsRefused(t *testing.T) {
	t.Parallel()

	// Two entries, one username. Binding as whichever came back first
	// would make the authenticated identity depend on server-side
	// ordering.
	dir := newDirectory().Add(
		ldaptest.User("uid=alice,ou=contractors,"+baseDN, "other").With("uid", "alice"),
	)

	auth := searchAuth(t, dir, ldapauth.WithUserSearch(baseDN, "(uid={{username}})"))

	_, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if !errors.Is(err, ldapauth.ErrAmbiguousUser) {
		t.Fatalf("err = %v, want ErrAmbiguousUser", err)
	}
}

func TestAttributesAreMapped(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithDisplayNameAttribute("cn"),
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithAttributes("objectClass"),
	)

	p, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if p.GetDisplayName() != "Alice Example" {
		t.Errorf("DisplayName = %q, want %q", p.GetDisplayName(), "Alice Example")
	}

	if p.GetEmail() != "alice@example.com" {
		t.Errorf("Email = %q, want %q", p.GetEmail(), "alice@example.com")
	}

	if got := p.GetAttribute("objectclass"); got != "inetOrgPerson" {
		t.Errorf("Attribute lookup is case-sensitive: got %q", got)
	}

	if got := p.GetAttribute("nosuchattribute"); got != "" {
		t.Errorf("missing attribute = %q, want empty", got)
	}
}

func TestDirectBindReadsAttributesOverTheUsersOwnConnection(t *testing.T) {
	t.Parallel()

	// The deployment with no service account at all: the user's freshly
	// bound connection is what reads their entry.
	dir := newDirectory()
	auth := directAuth(t, dir, ldapauth.WithEmailAttribute("mail"))

	p, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if p.GetEmail() != "alice@example.com" {
		t.Errorf("Email = %q, want it read over the user's own connection", p.GetEmail())
	}

	for _, bind := range dir.Binds() {
		if bind.DN == serviceDN {
			t.Fatal("a service bind happened in a configuration with no service account")
		}
	}
}

func TestAuthenticateAfterCloseIsErrClosed(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory())

	if err := auth.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := auth.Close(); err != nil {
		t.Fatalf("second Close: %v, want nil — Close is idempotent", err)
	}

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); !errors.Is(err, ldapauth.ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

func TestCancelledContextStopsTheRequest(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := auth.Authenticate(ctx, "alice", alicePassword)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestAuthErrorCarriesTheResultCode(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory())

	_, err := auth.Authenticate(testContext(t), "alice", "wrong")

	var authErr *ldapauth.AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want an *AuthError", err)
	}

	if authErr.ResultCode != ldap.LDAPResultInvalidCredentials {
		t.Errorf("ResultCode = %d, want %d", authErr.ResultCode, ldap.LDAPResultInvalidCredentials)
	}

	if authErr.Op == "" {
		t.Error("Op is empty; the error should say which step failed")
	}
}

func TestUsernameRedactionReachesTheError(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(), ldapauth.WithUsernameRedaction())

	_, err := auth.Authenticate(testContext(t), "alice", "wrong")
	if err == nil {
		t.Fatal("Authenticate succeeded with the wrong password")
	}

	if strings.Contains(err.Error(), "alice") {
		t.Errorf("error %q leaks the username under WithUsernameRedaction", err)
	}
}

func TestLookupNeedsNoPassword(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir, ldapauth.WithEmailAttribute("mail"))

	p, err := auth.Lookup(testContext(t), "alice")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if p.GetEmail() != "alice@example.com" {
		t.Errorf("Email = %q, want it populated", p.GetEmail())
	}

	for _, bind := range dir.Binds() {
		if bind.DN == aliceDN {
			t.Fatal("Lookup bound as the user; it is supposed to need no password")
		}
	}
}

func TestLookupDistinguishesAMissingUser(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory())

	_, err := auth.Lookup(testContext(t), "nobody")
	if !errors.Is(err, ldapauth.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound — there is no oracle to protect here", err)
	}
}

func TestHealthCheckProbesTheDirectory(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir)

	if err := auth.HealthCheck(testContext(t)); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}

	dir.SetDown(memoryURL, true)

	if err := auth.HealthCheck(testContext(t)); err == nil {
		t.Fatal("HealthCheck succeeded against a directory that is down")
	}
}
