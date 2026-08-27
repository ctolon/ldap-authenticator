// Command metrics implements the Metrics interface, which is how numbers
// leave this package without a metrics library entering it.
//
//	go run ./examples/metrics
//
// The adapter here counts into maps and prints a summary. A Prometheus one
// is the same shape with a CounterVec in place of the map — about twenty
// lines, and those twenty lines are cheaper than everybody who imports
// this package also importing a metrics library.
package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const peopleDN = "ou=people,dc=example,dc=com"

// collector implements ldapauth.Metrics.
//
// It embeds NoopMetrics, and that is not optional advice: the interface
// will grow methods in future 1.x releases as the package finds things
// worth counting, and the embedded no-op is what keeps that from breaking
// this build.
type collector struct {
	ldapauth.NoopMetrics

	mu sync.Mutex

	attempts map[string]int
	cache    map[string]int
	conns    map[string]int
	retries  int
	slowest  time.Duration
	inUse    int
	idle     int
}

func newCollector() *collector {
	return &collector{
		attempts: map[string]int{},
		cache:    map[string]int{},
		conns:    map[string]int{},
	}
}

// AuthAttempt is the one to alert on. The result values are a closed set —
// success, invalid_credentials, rejected, error — so they are safe as a
// label without unbounded cardinality.
func (c *collector) AuthAttempt(result string, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.attempts[result]++

	if d > c.slowest {
		c.slowest = d
	}
}

// CacheEvent reports hits, misses, negative hits, coalesced requests, and
// cache errors.
func (c *collector) CacheEvent(event string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[event]++
}

// RetryScheduled reports a retriable failure that will be tried again. A
// rising rate here means the transport is unreliable: retries are hiding
// it from your users, which is what they are for, but the problem is still
// there.
func (c *collector) RetryScheduled(string, int, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.retries++
}

// ConnOpened reports a new connection to the directory.
func (c *collector) ConnOpened(string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.conns["opened"]++
}

// ConnClosed reports a connection being discarded, with a short reason. A
// rising "unhealthy" rate usually means an idle timeout somewhere in the
// path is shorter than WithPoolMaxLifetime.
func (c *collector) ConnClosed(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.conns[reason]++
}

// PoolStats reports occupancy after a checkout or a return. In-use sitting
// at the configured size means requests are queuing on pool slots.
func (c *collector) PoolStats(inUse, idle int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.inUse, c.idle = inUse, idle
}

func (c *collector) report() {
	c.mu.Lock()
	defer c.mu.Unlock()

	fmt.Println("authentication attempts:")
	printCounts(c.attempts)

	fmt.Println("\ncache:")
	printCounts(c.cache)

	fmt.Println("\nconnections:")
	printCounts(c.conns)

	fmt.Printf("\nretries scheduled: %d\n", c.retries)
	fmt.Printf("slowest attempt:   %s\n", c.slowest.Round(time.Microsecond))
	fmt.Printf("pool at the end:   %d in use, %d idle\n", c.inUse, c.idle)
}

func printCounts(counts map[string]int) {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		fmt.Printf("  %-20s %d\n", key, counts[key])
	}
}

func main() {
	metrics := newCollector()

	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(directory().Dialer()),
		ldapauth.WithServiceAccount("cn=svc,dc=example,dc=com", "svc-password"),
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithMetrics(metrics),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}

	defer func() { _ = auth.Close() }()

	ctx := context.Background()

	// A little of everything, so that every counter moves.
	for range 3 {
		_, _ = auth.Authenticate(ctx, "alice", "s3cret")
	}

	for range 2 {
		_, _ = auth.Authenticate(ctx, "alice", "wrong")
	}

	_, _ = auth.Authenticate(ctx, "nobody", "whatever")
	_, _ = auth.Authenticate(ctx, "alice", "")
	_ = auth.HealthCheck(ctx)

	metrics.report()

	stats := auth.Stats(ctx)
	fmt.Printf("\nStats: %+v\n", stats)
}

func directory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User("uid=alice,"+peopleDN, "s3cret").
			With("uid", "alice").With("objectClass", "inetOrgPerson"),
		ldaptest.User("cn=svc,dc=example,dc=com", "svc-password").
			With("objectClass", "person"),
	)
}
