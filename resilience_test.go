package ldapauth_test

import (
	"context"
	"errors"
	"fmt"
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

	if p.DN != aliceDN {
		t.Errorf("DN = %q, want %q", p.DN, aliceDN)
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

	stats := auth.Stats()

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

			if p.Username != username {
				errs <- fmt.Errorf("got principal for %q while authenticating %q", p.Username, username)
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
