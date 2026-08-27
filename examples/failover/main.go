// Command failover shows what happens when a directory replica goes away.
//
//	go run ./examples/failover
//
// Three things are worth watching in the output: the first login pays one
// connection timeout for the dead server and then succeeds against the
// live one; the next ones do not pay it again, because the cooldown moved
// the dead server to the back of the queue; and when the dead server comes
// back, it is picked up again once the cooldown expires.
//
// The cooldown reorders the queue. It never removes a server from it —
// every URL is tried before a call fails, so a cooldown cannot turn a slow
// directory into an outage.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const (
	peopleDN = "ou=people,dc=example,dc=com"

	primary = "ldap://dc1.example.com"
	replica = "ldap://dc2.example.com"
)

// clock is advanced by hand so that a cooldown can be watched expiring
// without waiting for one.
type clock struct {
	now time.Time
	c   chan struct{}
}

func newClock() *clock {
	c := &clock{now: time.Now(), c: make(chan struct{}, 1)}
	c.c <- struct{}{}

	return c
}

func (c *clock) Now() time.Time {
	<-c.c
	defer func() { c.c <- struct{}{} }()

	return c.now
}

func (c *clock) advance(d time.Duration) {
	<-c.c
	defer func() { c.c <- struct{}{} }()

	c.now = c.now.Add(d)
}

func main() {
	dir := directory()
	clk := newClock()

	auth, err := ldapauth.New(
		// Ordered by preference: the local replica first, the remote one
		// behind it. FailoverRoundRobin or FailoverRandom are for when
		// the servers are equivalent and every process starting at once
		// should not send every bind to the same one.
		ldapauth.WithURLs(primary, replica),
		ldapauth.WithFailoverPolicy(ldapauth.FailoverInOrder),
		ldapauth.WithFailoverCooldown(30*time.Second),

		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithClock(clk.Now),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithoutRetry(),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}

	defer func() { _ = auth.Close() }()

	ctx := context.Background()

	step(ctx, auth, dir, "both servers up")

	fmt.Println("-- dc1 goes down --")
	dir.SetDown(primary, true)

	step(ctx, auth, dir, "first login after the outage: dc1 is tried, fails, dc2 answers")
	step(ctx, auth, dir, "second login: dc1 is in its cooldown and tried last")
	step(ctx, auth, dir, "third login: still in the cooldown")

	fmt.Println("-- dc1 comes back, and the cooldown expires --")
	dir.SetDown(primary, false)
	clk.advance(31 * time.Second)

	step(ctx, auth, dir, "dc1 is preferred again")

	fmt.Println("-- both servers down --")
	dir.SetDown(primary, true)
	dir.SetDown(replica, true)

	step(ctx, auth, dir, "every URL is still tried before the call fails")
}

func step(ctx context.Context, auth *ldapauth.Client, dir *ldaptest.Directory, what string) {
	dir.Reset()

	_, err := auth.Authenticate(ctx, "alice", "s3cret")

	stats := auth.Stats(ctx)

	fmt.Printf("%s\n", what)

	switch {
	case err == nil:
		for _, bind := range dir.Binds() {
			fmt.Printf("   bound on %s\n", bind.URL)
		}
	case errors.Is(err, ldapauth.ErrNoServerAvailable):
		fmt.Printf("   no server available\n")
	default:
		fmt.Printf("   failed: %v\n", err)
	}

	fmt.Printf("   healthy servers: %d of %d\n\n", stats.HealthyServers, stats.Servers)
}

func directory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User("uid=alice,"+peopleDN, "s3cret").
			With("uid", "alice").With("objectClass", "inetOrgPerson"),
	)
}
