package ldapauth_test

import (
	"errors"
	"testing"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

func TestCacheServesRepeatLogins(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir, ldapauth.WithCache(time.Minute))

	for range 5 {
		if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}

	if binds := len(dir.Binds()); binds > 2 {
		t.Errorf("binds = %d, want at most 2: the service bind and one user bind", binds)
	}

	if entries := auth.Stats(testContext(t)).CacheEntries; entries != 1 {
		t.Errorf("CacheEntries = %d, want 1", entries)
	}
}

func TestCacheIsKeyedByThePassword(t *testing.T) {
	t.Parallel()

	// A cache keyed by username alone would let the second, wrong password
	// ride in on the first, right one.
	auth := searchAuth(t, newDirectory(), ldapauth.WithCache(time.Minute))

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	_, err := auth.Authenticate(testContext(t), "alice", "wrong")
	if !errors.Is(err, ldapauth.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestCacheExpires(t *testing.T) {
	t.Parallel()

	clock := newClock()
	dir := newDirectory()

	auth := searchAuth(t, dir,
		ldapauth.WithClock(clock.Now),
		ldapauth.WithCache(30*time.Second),
		ldapauth.WithPoolHealthCheck(false),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	before := len(dir.Binds())

	clock.Advance(31 * time.Second)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate after expiry: %v", err)
	}

	if len(dir.Binds()) == before {
		t.Error("the expired entry was still served from cache")
	}
}

func TestNegativeCacheAbsorbsRepeatedFailures(t *testing.T) {
	t.Parallel()

	// What this buys: a client looping on a stale password stops reaching
	// the directory, and so stops counting against a lockout policy.
	dir := newDirectory()

	auth := searchAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithNegativeCache(time.Minute),
	)

	for range 5 {
		if _, err := auth.Authenticate(testContext(t), "alice", "wrong"); !errors.Is(err, ldapauth.ErrInvalidCredentials) {
			t.Fatalf("err = %v, want ErrInvalidCredentials", err)
		}
	}

	userBinds := 0

	for _, bind := range dir.Binds() {
		if bind.DN == aliceDN {
			userBinds++
		}
	}

	if userBinds != 1 {
		t.Errorf("user binds = %d, want 1: the rest should have been served from the negative cache", userBinds)
	}
}

func TestFailuresThatAreNotAboutTheCredentialAreNotCached(t *testing.T) {
	t.Parallel()

	// A directory that is down says nothing about whether the password is
	// right. Caching that would serve the outage back for the whole TTL.
	dir := newDirectory()
	dir.SetDown(memoryURL, true)

	auth := searchAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithNegativeCache(time.Minute),
		ldapauth.WithoutRetry(),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err == nil {
		t.Fatal("Authenticate succeeded against a directory that is down")
	}

	if entries := auth.Stats(testContext(t)).CacheEntries; entries != 0 {
		t.Errorf("CacheEntries = %d, want 0", entries)
	}

	dir.SetDown(memoryURL, false)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate once the directory came back: %v", err)
	}
}

func TestInvalidateUserDropsTheEntry(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir, ldapauth.WithCache(time.Minute))

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	dropped, err := auth.InvalidateUser(testContext(t), "ALICE")
	if err != nil {
		t.Fatalf("InvalidateUser: %v", err)
	}

	if dropped != 1 {
		t.Errorf("InvalidateUser dropped %d entries, want 1 — the match should be case-insensitive", dropped)
	}

	before := len(dir.Binds())

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if len(dir.Binds()) == before {
		t.Error("the invalidated entry was still served from cache")
	}
}

func TestInvalidateAllEmptiesTheCache(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(), ldapauth.WithCache(time.Minute))

	for _, user := range []struct{ name, password string }{
		{"alice", alicePassword},
		{"bob", bobPassword},
	} {
		if _, err := auth.Authenticate(testContext(t), user.name, user.password); err != nil {
			t.Fatalf("Authenticate %s: %v", user.name, err)
		}
	}

	dropped, err := auth.InvalidateAll(testContext(t))
	if err != nil {
		t.Fatalf("InvalidateAll: %v", err)
	}

	if dropped != 2 {
		t.Errorf("InvalidateAll dropped %d entries, want 2", dropped)
	}

	if entries := auth.Stats(testContext(t)).CacheEntries; entries != 0 {
		t.Errorf("CacheEntries = %d, want 0", entries)
	}
}

func TestCacheIsBounded(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithNegativeCache(time.Minute),
		ldapauth.WithCacheSize(4),
	)

	for i := range 20 {
		_, _ = auth.Authenticate(testContext(t), "alice", string(rune('a'+i)))
	}

	if entries := auth.Stats(testContext(t)).CacheEntries; entries > 4 {
		t.Errorf("CacheEntries = %d, want at most the configured 4", entries)
	}
}

func TestCachedPrincipalsAreCopies(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithMemberOfGroups(),
	)

	first, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	principal, ok := ldapauth.AsPrincipal(first)
	if !ok {
		t.Fatalf("Authenticate returned %T, want the default *Principal", first)
	}

	principal.Groups[0] = "tampered"
	principal.DN = "cn=tampered"

	second, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if second.GetDN() == "cn=tampered" || second.GetGroups()[0] == "tampered" {
		t.Fatal("editing a principal changed what the cache serves next")
	}
}

func TestCaseFoldedUsernamesShareACacheEntry(t *testing.T) {
	t.Parallel()

	dir := newDirectory()

	auth := searchAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCaseFoldUsername(),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	before := len(dir.Binds())

	if _, err := auth.Authenticate(testContext(t), "ALICE", alicePassword); err != nil {
		t.Fatalf("Authenticate with different case: %v", err)
	}

	if len(dir.Binds()) != before {
		t.Error("ALICE did not share alice's cache entry under WithCaseFoldUsername")
	}
}

func TestUsernameSentToTheDirectoryIsNeverFolded(t *testing.T) {
	t.Parallel()

	// Folding is a cache-key decision. How usernames compare is the
	// directory's decision, and its matching rules are not knowable here.
	dir := newDirectory()

	auth := searchAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCaseFoldUsername(),
	)

	_, _ = auth.Authenticate(testContext(t), "ALICE", alicePassword)

	found := false

	for _, search := range dir.Searches() {
		if search.Filter == "(uid=ALICE)" {
			found = true
		}
	}

	if !found {
		t.Errorf("searches = %v, want the username sent as supplied", dir.Filters())
	}
}

func TestMetricsHooksAreCalled(t *testing.T) {
	t.Parallel()

	m := &recordingMetrics{}

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithMetrics(m),
		ldapauth.WithCache(time.Minute),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if _, err := auth.Authenticate(testContext(t), "alice", "wrong"); err == nil {
		t.Fatal("Authenticate succeeded with the wrong password")
	}

	if got := m.results; len(got) != 2 {
		t.Fatalf("AuthAttempt calls = %d, want 2", len(got))
	}

	if m.results[0] != ldapauth.ResultSuccess {
		t.Errorf("first result = %q, want %q", m.results[0], ldapauth.ResultSuccess)
	}

	if m.results[1] != ldapauth.ResultInvalidCredentials {
		t.Errorf("second result = %q, want %q", m.results[1], ldapauth.ResultInvalidCredentials)
	}

	if m.opened == 0 {
		t.Error("ConnOpened was never called")
	}
}

// recordingMetrics embeds NoopMetrics, which is what implementations are
// told to do so that a method added to the interface later does not break
// them. This test is also that promise's regression test.
type recordingMetrics struct {
	ldapauth.NoopMetrics

	results []string

	opened int
}

func (m *recordingMetrics) AuthAttempt(result string, _ time.Duration) {
	m.results = append(m.results, result)
}

func (m *recordingMetrics) ConnOpened(string) { m.opened++ }
