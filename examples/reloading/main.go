// Command reloading rotates the service account password without
// restarting the process.
//
//	go run ./examples/reloading
//
// The password is read once, when the Client is built, and there is
// deliberately no way to change it underneath a running one — a field that
// can change while requests read it needs a lock, and that lock would sit
// on the hot path of every login to serve a rotation that happens twice a
// year.
//
// So the answer is to build a new Client and swap the pointer.
// ldapauth.Reloadable is that, and the part it gets right is the ordering:
// the old Client is closed after the swap, never before, and closing it
// does not interrupt the requests already running on it.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const (
	peopleDN  = "ou=people,dc=example,dc=com"
	serviceDN = "cn=svc,dc=example,dc=com"
)

func main() {
	dir := directory("first-service-password")

	build := func(servicePassword string) (*ldapauth.Client, error) {
		return ldapauth.New(
			ldapauth.WithURL("ldap://in-memory"),
			ldapauth.WithDialer(dir.Dialer()),
			ldapauth.WithServiceAccount(serviceDN, servicePassword),
			ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		)
	}

	first, err := build("first-service-password")
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}

	auth := ldapauth.NewReloadable(first)

	defer func() { _ = auth.Close() }()

	// Traffic, throughout. Nothing below stops it.
	stop := make(chan struct{})

	var wg sync.WaitGroup

	var attempts, failures int64

	var counters sync.Mutex

	for range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for {
				select {
				case <-stop:
					return
				default:
				}

				_, err := auth.Authenticate(context.Background(), "alice", "s3cret")

				counters.Lock()
				attempts++

				if err != nil {
					failures++
				}

				counters.Unlock()
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)

	fmt.Println("the secret manager reports a new service account password")

	// What a real reload looks like. Note the ordering: build, check,
	// swap, then close what was replaced.
	dir.Add(ldaptest.User(serviceDN, "second-service-password").With("objectClass", "person"))

	next, err := build("second-service-password")
	if err != nil {
		// A failed reload leaves the working client in place. Installing
		// nothing would be worse than an old password.
		fmt.Fprintln(os.Stderr, "reload failed, keeping the old client:", err)

		return
	}

	previous := auth.Replace(next)

	fmt.Println("swapped")

	// Closing the replaced client does not interrupt requests already
	// running on it; they finish against connections closed as they are
	// released. By now nothing new is choosing it, because the swap
	// already happened.
	if err := previous.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "closing the replaced client:", err)
	}

	time.Sleep(50 * time.Millisecond)

	close(stop)
	wg.Wait()

	counters.Lock()
	defer counters.Unlock()

	fmt.Printf("\n%d logins across the rotation, %d of them failed\n", attempts, failures)

	if failures > 0 {
		fmt.Println("that should be zero — the rotation was not transparent")
		os.Exit(1)
	}

	fmt.Println("the rotation was invisible to every caller")

	if _, err := auth.Authenticate(context.Background(), "alice", "s3cret"); err != nil {
		fmt.Fprintln(os.Stderr, "after the rotation:", err)
		os.Exit(1)
	}

	// And the old password no longer works anywhere, which is the point
	// of having rotated it.
	stale, err := build("first-service-password")
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)

		return
	}

	defer func() { _ = stale.Close() }()

	dir.Add(ldaptest.User(serviceDN, "second-service-password").With("objectClass", "person"))

	if _, err := stale.Authenticate(context.Background(), "alice", "s3cret"); err == nil {
		fmt.Println("the old service password still works, which it should not")
	} else if errors.Is(err, ldapauth.ErrInvalidCredentials) || err != nil {
		fmt.Println("a client still holding the old service password is refused, as it should be")
	}
}

func directory(servicePassword string) *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User("uid=alice,"+peopleDN, "s3cret").
			With("uid", "alice").With("objectClass", "inetOrgPerson"),
		ldaptest.User(serviceDN, servicePassword).With("objectClass", "person"),
	)
}
