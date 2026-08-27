package ldapauth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

// recordingCache is a Cache that remembers what it was asked, so that a
// test can assert on the contract rather than on the outcome: what keys
// look like, what a store is told, and what happens when it fails.
type recordingCache struct {
	inner ldapauth.Cache

	mu sync.Mutex

	keys []string

	usernames []string

	failGet error

	failSet error
}

func newRecordingCache() *recordingCache {
	return &recordingCache{inner: ldapauth.NewMemoryCache(64, nil)}
}

func (c *recordingCache) Get(ctx context.Context, key string) (ldapauth.Identity, bool, error) {
	c.mu.Lock()
	c.keys = append(c.keys, key)
	failure := c.failGet
	c.mu.Unlock()

	if failure != nil {
		return nil, false, failure
	}

	return c.inner.Get(ctx, key)
}

func (c *recordingCache) Set(
	ctx context.Context,
	key, username string,
	identity ldapauth.Identity,
	ttl time.Duration,
) error {
	c.mu.Lock()
	c.usernames = append(c.usernames, username)
	failure := c.failSet
	c.mu.Unlock()

	if failure != nil {
		return failure
	}

	return c.inner.Set(ctx, key, username, identity, ttl)
}

func (c *recordingCache) InvalidateUser(ctx context.Context, username string) (int, error) {
	return c.inner.InvalidateUser(ctx, username)
}

func (c *recordingCache) InvalidateAll(ctx context.Context) (int, error) {
	return c.inner.InvalidateAll(ctx)
}

func (c *recordingCache) Len(ctx context.Context) (int, error) { return c.inner.Len(ctx) }

func (c *recordingCache) seenKeys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]string(nil), c.keys...)
}

func TestACustomCacheStoreIsUsed(t *testing.T) {
	t.Parallel()

	store := newRecordingCache()
	dir := newDirectory()

	auth := searchAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheStore(store),
	)

	for range 3 {
		if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}

	if len(store.seenKeys()) != 3 {
		t.Errorf("the store was consulted %d times, want 3", len(store.seenKeys()))
	}

	if binds := len(dir.Binds()); binds > 2 {
		t.Errorf("binds = %d, want at most 2: the store should have served the rest", binds)
	}
}

func TestACacheStoreNeverSeesACredential(t *testing.T) {
	t.Parallel()

	store := newRecordingCache()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheStore(store),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	for _, key := range store.seenKeys() {
		if len(key) != 32 {
			t.Errorf("key is %d bytes, want a 32-byte HMAC digest", len(key))
		}

		for _, secret := range []string{alicePassword, "alice"} {
			if strings.Contains(key, secret) {
				t.Errorf("the key carries %q", secret)
			}
		}
	}

	// The username is passed unhashed alongside the key, and that is
	// documented: InvalidateUser cannot work without it.
	store.mu.Lock()
	usernames := append([]string(nil), store.usernames...)
	store.mu.Unlock()

	if len(usernames) != 1 || usernames[0] != "alice" {
		t.Errorf("usernames = %v, want [alice]", usernames)
	}
}

func TestACacheThatIsDownIsNotADirectoryThatIsDown(t *testing.T) {
	t.Parallel()

	store := newRecordingCache()
	store.failGet = errors.New("redis: connection refused")
	store.failSet = errors.New("redis: connection refused")

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheStore(store),
	)

	// Every call falls through to the directory and succeeds. A cache
	// outage must degrade performance, never availability.
	for range 3 {
		if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
			t.Fatalf("Authenticate with a broken cache: %v", err)
		}
	}
}

func TestACacheThatCannotCountLeavesStatsAtMinusOne(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheStore(uncountableCache{ldapauth.NewMemoryCache(8, nil)}),
	)

	if entries := auth.Stats(testContext(t)).CacheEntries; entries != -1 {
		t.Errorf("CacheEntries = %d, want -1", entries)
	}
}

type uncountableCache struct{ ldapauth.Cache }

func (uncountableCache) Len(context.Context) (int, error) {
	return 0, errors.New("counting is not cheap here")
}

func TestASharedSecretMakesTwoAuthenticatorsAgreeOnKeys(t *testing.T) {
	t.Parallel()

	// The multi-replica case: two processes, one cache. Without a shared
	// secret each derives its own keys and the shared cache never hits,
	// which is a silent and expensive way to be wrong.
	secret := []byte("a-shared-secret-at-least-16-bytes")
	store := newRecordingCache()
	dir := newDirectory()

	first := searchAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheStore(store),
		ldapauth.WithCacheSecret(secret),
	)

	second := searchAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheStore(store),
		ldapauth.WithCacheSecret(secret),
	)

	if _, err := first.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}

	before := len(dir.Binds())

	if _, err := second.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("second Authenticate: %v", err)
	}

	if len(dir.Binds()) != before {
		t.Error("the second authenticator missed the first one's cache entry")
	}
}

func TestWithoutASharedSecretTwoAuthenticatorsDisagree(t *testing.T) {
	t.Parallel()

	store := newRecordingCache()
	dir := newDirectory()

	first := searchAuth(t, dir, ldapauth.WithCache(time.Minute), ldapauth.WithCacheStore(store))
	second := searchAuth(t, dir, ldapauth.WithCache(time.Minute), ldapauth.WithCacheStore(store))

	if _, err := first.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}

	before := len(dir.Binds())

	if _, err := second.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("second Authenticate: %v", err)
	}

	if len(dir.Binds()) == before {
		t.Error("two authenticators shared a cache entry without a shared secret")
	}
}

func TestACacheStoreWithoutCachingIsAConfigurationError(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithCacheStore(ldapauth.NewMemoryCache(8, nil)),
	)
}

func TestAShortCacheSecretIsRefused(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheSecret([]byte("too short")),
	)
}

func TestConcurrentIdenticalLoginsCollapseIntoOne(t *testing.T) {
	t.Parallel()

	// The stampede the cache cannot absorb on its own: a hundred requests
	// arriving before the first one has finished.
	dir := newDirectory()

	release := make(chan struct{})

	dir.BindHook = func(dn, _ string) error {
		if dn == aliceDN {
			<-release
		}

		return nil
	}

	auth := searchAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithPoolHealthCheck(false),
	)

	const callers = 24

	var wg sync.WaitGroup

	errs := make(chan error, callers)

	for range callers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
				errs <- err
			}
		}()
	}

	// Let them pile up behind the one bind that is in flight.
	time.Sleep(50 * time.Millisecond)
	close(release)

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	userBinds := 0

	for _, bind := range dir.Binds() {
		if bind.DN == aliceDN {
			userBinds++
		}
	}

	if userBinds != 1 {
		t.Errorf("user binds = %d, want 1: the rest should have been coalesced", userBinds)
	}
}

func TestCoalescingDoesNotShareBetweenDifferentCredentials(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir, ldapauth.WithCache(time.Minute))

	var wg sync.WaitGroup

	results := make(chan string, 2)

	for _, user := range []struct{ name, password string }{
		{"alice", alicePassword},
		{"bob", bobPassword},
	} {
		wg.Add(1)

		go func() {
			defer wg.Done()

			identity, err := auth.Authenticate(testContext(t), user.name, user.password)
			if err != nil {
				results <- "error: " + err.Error()

				return
			}

			results <- identity.GetUsername()
		}()
	}

	wg.Wait()
	close(results)

	seen := map[string]bool{}

	for name := range results {
		seen[name] = true
	}

	if !seen["alice"] || !seen["bob"] {
		t.Errorf("results = %v, want one for each caller", seen)
	}
}

func TestOneCallerGivingUpDoesNotCancelTheOthers(t *testing.T) {
	t.Parallel()

	// The failure this prevents: the first caller closes their browser,
	// their context is cancelled, and the authentication a hundred other
	// callers are waiting on dies with it.
	dir := newDirectory()

	release := make(chan struct{})
	arrived := make(chan struct{}, 1)

	dir.BindHook = func(dn, _ string) error {
		if dn != aliceDN {
			return nil
		}

		select {
		case arrived <- struct{}{}:
		default:
		}

		<-release

		return nil
	}

	auth := searchAuth(t, dir, ldapauth.WithCache(time.Minute), ldapauth.WithPoolHealthCheck(false))

	leaderCtx, cancelLeader := context.WithCancel(context.Background())

	leaderDone := make(chan error, 1)

	go func() {
		_, err := auth.Authenticate(leaderCtx, "alice", alicePassword)
		leaderDone <- err
	}()

	<-arrived

	waiterDone := make(chan error, 1)

	go func() {
		_, err := auth.Authenticate(context.Background(), "alice", alicePassword)
		waiterDone <- err
	}()

	// Give the waiter a moment to attach, then take the leader away.
	time.Sleep(50 * time.Millisecond)
	cancelLeader()

	close(release)

	if err := <-waiterDone; err != nil {
		t.Fatalf("the waiter failed because the leader gave up: %v", err)
	}

	<-leaderDone
}

func TestAWaiterDoesNotOutliveItsOwnDeadline(t *testing.T) {
	t.Parallel()

	dir := newDirectory()

	release := make(chan struct{})
	arrived := make(chan struct{}, 1)

	dir.BindHook = func(dn, _ string) error {
		if dn != aliceDN {
			return nil
		}

		select {
		case arrived <- struct{}{}:
		default:
		}

		<-release

		return nil
	}

	auth := searchAuth(t, dir, ldapauth.WithCache(time.Minute), ldapauth.WithPoolHealthCheck(false))

	go func() {
		_, _ = auth.Authenticate(context.Background(), "alice", alicePassword)
	}()

	<-arrived

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	started := time.Now()

	_, err := auth.Authenticate(ctx, "alice", alicePassword)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the waiter's own deadline", err)
	}

	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Errorf("the waiter blocked for %s past its own deadline", elapsed)
	}

	close(release)
}
