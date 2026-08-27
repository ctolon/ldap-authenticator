package ldapauth_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

const secondURL = "ldap://memory-2"

func TestPoolReusesServiceConnections(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir)

	const logins = 5

	for range logins {
		if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}

	opened, _ := dir.Conns()

	// One pooled service connection, plus one throwaway connection per
	// user bind. Anything more means the pool is not pooling.
	if opened != logins+1 {
		t.Errorf("connections opened = %d, want %d", opened, logins+1)
	}
}

func TestPoolRespectsItsSizeLimit(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		inFlight int
		peak     int
	)

	dir := newDirectory()
	dir.SearchHook = func(*ldap.SearchRequest) error {
		mu.Lock()
		inFlight++

		if inFlight > peak {
			peak = inFlight
		}

		mu.Unlock()

		time.Sleep(2 * time.Millisecond)

		mu.Lock()
		inFlight--
		mu.Unlock()

		return nil
	}

	auth := searchAuth(t, dir, ldapauth.WithPoolSize(2), ldapauth.WithPoolHealthCheck(false))

	var wg sync.WaitGroup

	for range 12 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, _ = auth.Authenticate(testContext(t), "alice", alicePassword)
		}()
	}

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	if peak > 2 {
		t.Errorf("peak concurrent searches = %d, want at most the pool size of 2", peak)
	}
}

func TestPoolRetiresConnectionsPastTheirLifetime(t *testing.T) {
	t.Parallel()

	clock := newClock()
	dir := newDirectory()

	auth := searchAuth(t, dir,
		ldapauth.WithClock(clock.Now),
		ldapauth.WithPoolMaxLifetime(time.Minute),
		ldapauth.WithPoolHealthCheck(false),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	before, _ := dir.Conns()

	clock.Advance(2 * time.Minute)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate after the lifetime expired: %v", err)
	}

	after, _ := dir.Conns()

	// Two new connections: the replacement pooled one and the user bind.
	if after-before != 2 {
		t.Errorf("connections opened across the expiry = %d, want 2", after-before)
	}
}

func TestPoolDiscardsConnectionsThatFailed(t *testing.T) {
	t.Parallel()

	var fail atomic.Bool

	dir := newDirectory()
	dir.SearchHook = func(*ldap.SearchRequest) error {
		if fail.Load() {
			return ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset"))
		}

		return nil
	}

	auth := searchAuth(t, dir, ldapauth.WithPoolHealthCheck(false), ldapauth.WithoutRetry())

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	_, closedBefore := dir.Conns()

	fail.Store(true)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err == nil {
		t.Fatal("Authenticate succeeded against a directory returning network errors")
	}

	_, closedAfter := dir.Conns()

	if closedAfter <= closedBefore {
		t.Error("the connection that failed was returned to the pool instead of being closed")
	}
}

func TestFailoverSkipsADeadServer(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	dir.SetDown(memoryURL, true)

	auth := newAuthenticator(t, dir,
		ldapauth.WithURL(secondURL),
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(serviceDN, servicePassword),
	)

	p, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if p.GetDN() != aliceDN {
		t.Errorf("DN = %q, want %q", p.GetDN(), aliceDN)
	}

	for _, bind := range dir.Binds() {
		if bind.URL != secondURL {
			t.Errorf("bind went to %q, want the healthy server %q", bind.URL, secondURL)
		}
	}
}

func TestFailoverCooldownStopsRetryingADeadServer(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int64

	dir := newDirectory()
	dir.SetDown(memoryURL, true)
	dir.DialHook = func(url string) error {
		if url == memoryURL {
			attempts.Add(1)
		}

		return nil
	}

	auth := newAuthenticator(t, dir,
		ldapauth.WithURL(secondURL),
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(serviceDN, servicePassword),
		ldapauth.WithFailoverCooldown(time.Minute),
		ldapauth.WithPoolHealthCheck(false),
	)

	for range 4 {
		if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}

	if got := attempts.Load(); got > 2 {
		t.Errorf("dials to the dead server = %d, want the cooldown to hold it to one or two", got)
	}
}

func TestEveryServerDownIsErrNoServerAvailable(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	dir.SetDown(memoryURL, true)
	dir.SetDown(secondURL, true)

	auth := newAuthenticator(t, dir,
		ldapauth.WithURL(secondURL),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithoutRetry(),
	)

	_, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if !errors.Is(err, ldapauth.ErrNoServerAvailable) {
		t.Fatalf("err = %v, want ErrNoServerAvailable", err)
	}
}

func TestStatsReportFailoverHealth(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	dir.SetDown(memoryURL, true)

	auth := newAuthenticator(t, dir,
		ldapauth.WithURL(secondURL),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithFailoverCooldown(time.Minute),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	stats := auth.Stats(testContext(t))

	if stats.Servers != 2 {
		t.Errorf("Servers = %d, want 2", stats.Servers)
	}

	if stats.HealthyServers != 1 {
		t.Errorf("HealthyServers = %d, want 1", stats.HealthyServers)
	}
}

func TestTransientFailuresAreRetried(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int64

	dir := newDirectory()
	dir.DialHook = func(string) error {
		if attempts.Add(1) <= 2 {
			return ldap.NewError(ldap.ErrorNetwork, errors.New("connection refused"))
		}

		return nil
	}

	auth := newAuthenticator(t, dir,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithRetry(3),
		ldapauth.WithRetryBackoff(time.Millisecond, 2*time.Millisecond, 2),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if got := attempts.Load(); got != 3 {
		t.Errorf("dial attempts = %d, want 3: two failures then a success", got)
	}
}

func TestRejectedCredentialsAreNeverRetried(t *testing.T) {
	t.Parallel()

	// The reason this matters: a directory with a lockout policy counts
	// failed binds. A library that retried them would turn one typo into
	// three strikes.
	dir := newDirectory()

	auth := newAuthenticator(t, dir,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithRetry(5),
		ldapauth.WithRetryBackoff(time.Millisecond, 2*time.Millisecond, 2),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", "wrong"); !errors.Is(err, ldapauth.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}

	if binds := dir.Binds(); len(binds) != 1 {
		t.Fatalf("binds = %d, want exactly 1", len(binds))
	}
}

func TestRetryGivesUpAfterTheAttemptBudget(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int64

	dir := newDirectory()
	dir.DialHook = func(string) error {
		attempts.Add(1)

		return ldap.NewError(ldap.ErrorNetwork, errors.New("connection refused"))
	}

	auth := newAuthenticator(t, dir,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithRetry(2),
		ldapauth.WithRetryBackoff(time.Millisecond, 2*time.Millisecond, 2),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err == nil {
		t.Fatal("Authenticate succeeded against a directory that never answered")
	}

	if got := attempts.Load(); got != 3 {
		t.Errorf("dial attempts = %d, want 3: the first plus two retries", got)
	}
}

func TestConcurrentAuthenticationIsSafe(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir, ldapauth.WithMemberOfGroups(), ldapauth.WithNestedGroups())

	var wg sync.WaitGroup

	errs := make(chan error, 40)

	for i := range 40 {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			username, password := "alice", alicePassword
			if i%2 == 1 {
				username, password = "bob", bobPassword
			}

			p, err := auth.Authenticate(testContext(t), username, password)
			if err != nil {
				errs <- fmt.Errorf("%s: %w", username, err)

				return
			}

			if p.GetUsername() != username {
				errs <- fmt.Errorf("got principal for %q while authenticating %q", p.GetUsername(), username)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestCustomDialerIsUsed(t *testing.T) {
	t.Parallel()

	dir := newDirectory()

	var calls atomic.Int64

	auth := newAuthenticator(t, dir,
		ldapauth.WithDialer(countingDialer{inner: dir.Dialer(), calls: &calls}),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if calls.Load() == 0 {
		t.Error("the custom dialer was never called")
	}
}

type countingDialer struct {
	inner ldapauth.Dialer
	calls *atomic.Int64
}

func (d countingDialer) DialContext(ctx context.Context, url string) (ldapauth.Conn, error) {
	d.calls.Add(1)

	return d.inner.DialContext(ctx, url)
}

func TestEverythingAtOnceUnderRace(t *testing.T) {
	t.Parallel()

	// A deliberate pile-up: every entry point, every background moving
	// part, and a shutdown underneath all of it. Nothing here asserts an
	// outcome — the assertions are the race detector's, and the only
	// failure this test can report on its own is a deadlock or a panic.
	dir := newDirectory()

	clock := newClock()

	auth := searchAuth(t, dir,
		ldapauth.WithClock(clock.Now),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithNestedGroups(),
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithNegativeCache(30*time.Second),
		ldapauth.WithPoolSize(4),
		ldapauth.WithPoolMinIdle(2),
		ldapauth.WithPoolMaxLifetime(time.Minute),
		ldapauth.WithPoolMaxIdleTime(30*time.Second),
		ldapauth.WithRetryBackoff(time.Millisecond, 2*time.Millisecond, 2),
	)

	ctx := testContext(t)

	stop := make(chan struct{})

	var wg sync.WaitGroup

	worker := func(fn func(i int)) {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}

				fn(i)
			}
		}()
	}

	// Successful logins, rejected logins, lookups, health checks, stats,
	// invalidation, a clock that keeps moving so the pool and the cache
	// keep expiring, and a server that comes and goes.
	worker(func(int) { _, _ = auth.Authenticate(ctx, "alice", alicePassword) })
	worker(func(int) { _, _ = auth.Authenticate(ctx, "bob", bobPassword) })
	worker(func(int) { _, _ = auth.Authenticate(ctx, "alice", "wrong") })
	worker(func(int) { _, _ = auth.Lookup(ctx, "alice") })
	worker(func(int) { _ = auth.HealthCheck(ctx) })
	worker(func(int) { _ = auth.Stats(ctx) })
	worker(func(int) { _, _ = auth.InvalidateUser(ctx, "alice") })
	worker(func(int) { clock.Advance(5 * time.Second) })
	worker(func(i int) { dir.SetDown(memoryURL, i%8 == 0) })

	time.Sleep(250 * time.Millisecond)

	// Close while everything is still running: the whole point is that
	// shutdown races with in-flight work rather than waiting politely for
	// a quiet moment.
	if err := auth.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	close(stop)
	wg.Wait()
}

func TestCloseIsSafeFromManyGoroutines(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory())

	var wg sync.WaitGroup

	for range 16 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if err := auth.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}

	wg.Wait()

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); !errors.Is(err, ldapauth.ErrClosed) {
		t.Errorf("err = %v, want ErrClosed", err)
	}
}

func TestPoolReturnsEveryConnectionItTookOut(t *testing.T) {
	t.Parallel()

	// A pool that leaked slots would deadlock rather than fail, and it
	// would do it under load rather than in a unit test. This is the
	// cheap version of that: exhaust the pool repeatedly, through both
	// the success and the failure paths, and require it to still be
	// empty at the end.
	var fail atomic.Bool

	dir := newDirectory()
	dir.SearchHook = func(*ldap.SearchRequest) error {
		if fail.Load() {
			return ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset"))
		}

		return nil
	}

	auth := searchAuth(t, dir,
		ldapauth.WithPoolSize(2),
		ldapauth.WithPoolHealthCheck(false),
		ldapauth.WithoutRetry(),
	)

	var wg sync.WaitGroup

	for i := range 40 {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			fail.Store(i%3 == 0)

			_, _ = auth.Authenticate(testContext(t), "alice", alicePassword)
		}(i)
	}

	wg.Wait()

	fail.Store(false)

	stats := auth.Stats(testContext(t))
	if stats.PoolInUse != 0 {
		t.Errorf("PoolInUse = %d after everything finished, want 0", stats.PoolInUse)
	}

	// And the pool still works, which is the part a leak would break.
	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate after the churn: %v", err)
	}
}

func TestPasswordLengthIsBounded(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir, ldapauth.WithPasswordMaxLength(32))

	_, err := auth.Authenticate(testContext(t), "alice", strings.Repeat("x", 33))
	if !errors.Is(err, ldapauth.ErrInvalidPassword) {
		t.Fatalf("err = %v, want ErrInvalidPassword", err)
	}

	if binds := len(dir.Binds()); binds != 0 {
		t.Errorf("binds = %d, want 0: an oversized password costs no round trip", binds)
	}
}

func TestIdleConnectionsAreReaped(t *testing.T) {
	t.Parallel()

	// The janitor is the only thing that closes an idle connection when
	// no traffic is arriving to notice it has aged out. Its tick is real
	// time — the expiry decision is not, which is what the clock is for.
	clock := newClock()
	dir := newDirectory()

	auth := searchAuth(t, dir,
		ldapauth.WithClock(clock.Now),
		ldapauth.WithPoolMaxIdleTime(4*time.Second),
		ldapauth.WithPoolHealthCheck(false),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if idle := auth.Stats(testContext(t)).PoolIdle; idle != 1 {
		t.Fatalf("PoolIdle = %d after one login, want 1", idle)
	}

	clock.Advance(time.Minute)

	deadline := time.Now().Add(10 * time.Second)

	for auth.Stats(testContext(t)).PoolIdle > 0 {
		if time.Now().After(deadline) {
			t.Fatal("the janitor never reaped the idle connection")
		}

		time.Sleep(20 * time.Millisecond)
	}
}

func TestPagingReachesTheWire(t *testing.T) {
	t.Parallel()

	// Active Directory truncates an unpaged search at 1000 entries and
	// says nothing about it, so a group search over a large directory
	// that is not paged is a group list that is quietly wrong.
	dir := newDirectory()

	auth := searchAuth(t, dir,
		ldapauth.WithPagingSize(500),
		ldapauth.WithGroupSearch(groupsDN, "(member={{user_dn}})"),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if paged := dir.PagedSearches(); paged == 0 {
		t.Error("WithPagingSize was configured but no search was paged")
	}
}

func TestDirectBindReadsThroughTheServiceAccountWhenThereIsOne(t *testing.T) {
	t.Parallel()

	// A directory may let a user bind while not letting them read their
	// own attributes, so a service account, where one is configured, is
	// the right identity for the lookup that follows a direct bind.
	dir := newDirectory()

	auth := newAuthenticator(t, dir,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithServiceAccount(serviceDN, servicePassword),
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithMemberOfGroups(),
	)

	identity, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if identity.GetEmail() != "alice@example.com" {
		t.Errorf("Email = %q, want it read", identity.GetEmail())
	}

	serviceBinds := 0

	for _, bind := range dir.Binds() {
		if bind.DN == serviceDN {
			serviceBinds++
		}
	}

	if serviceBinds == 0 {
		t.Error("the service account was configured but never bound")
	}
}

func TestAnUnreadableEntryStillAuthenticates(t *testing.T) {
	t.Parallel()

	// The bind succeeded, so the entry exists. Not being able to read it
	// is a directory permission to fix, not an authentication to fail.
	dir := newDirectory()
	dir.SearchHook = func(request *ldap.SearchRequest) error {
		if request.BaseDN == aliceDN {
			// A directory that hides the entry answers a base search
			// with no entries rather than with an error.
			request.Filter = "(objectClass=nothing-matches-this)"
		}

		return nil
	}

	auth := directAuth(t, dir, ldapauth.WithEmailAttribute("mail"))

	identity, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if identity.GetDN() != aliceDN {
		t.Errorf("DN = %q, want the bound DN", identity.GetDN())
	}

	if identity.GetEmail() != "" {
		t.Errorf("Email = %q, want empty when the entry could not be read", identity.GetEmail())
	}
}

func TestBackoffStopsWhenTheCallerGivesUp(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	dir.DialHook = func(string) error {
		return ldap.NewError(ldap.ErrorNetwork, errors.New("connection refused"))
	}

	auth := newAuthenticator(t, dir,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithRetry(50),
		ldapauth.WithRetryBackoff(50*time.Millisecond, time.Second, 2),
		ldapauth.WithRetryMaxElapsed(time.Minute),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	started := time.Now()

	_, err := auth.Authenticate(ctx, "alice", alicePassword)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context's deadline", err)
	}

	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Errorf("the retry loop ran for %s after the caller gave up", elapsed)
	}
}

func TestBackoffStopsWhenTheAuthenticatorCloses(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	dir.DialHook = func(string) error {
		return ldap.NewError(ldap.ErrorNetwork, errors.New("connection refused"))
	}

	auth := newAuthenticator(t, dir,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithRetry(50),
		ldapauth.WithRetryBackoff(200*time.Millisecond, 2*time.Second, 2),
		ldapauth.WithRetryMaxElapsed(time.Minute),
	)

	done := make(chan error, 1)

	go func() {
		_, err := auth.Authenticate(context.Background(), "alice", alicePassword)
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)

	if err := auth.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, ldapauth.ErrClosed) {
			t.Errorf("err = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closing did not interrupt the backoff")
	}
}

func TestRetryGivesUpOnTheElapsedBudget(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int64

	dir := newDirectory()
	dir.DialHook = func(string) error {
		attempts.Add(1)

		return ldap.NewError(ldap.ErrorNetwork, errors.New("connection refused"))
	}

	auth := newAuthenticator(t, dir,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithRetry(100),
		ldapauth.WithRetryBackoff(20*time.Millisecond, 40*time.Millisecond, 2),
		ldapauth.WithRetryMaxElapsed(120*time.Millisecond),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err == nil {
		t.Fatal("Authenticate succeeded against a directory that never answered")
	}

	// The budget, not the attempt count, is what stopped it — so the
	// attempts are far below the hundred that were allowed.
	if got := attempts.Load(); got > 20 {
		t.Errorf("dial attempts = %d, want the elapsed budget to have stopped it much sooner", got)
	}
}
