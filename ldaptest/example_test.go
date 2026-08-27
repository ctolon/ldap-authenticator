package ldaptest_test

import (
	"context"
	"errors"
	"fmt"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

// A directory in a map, with no server anywhere.
func ExampleNew() {
	dir := ldaptest.New(
		ldaptest.User("uid=alice,ou=people,dc=example,dc=com", "s3cret").
			With("uid", "alice").
			With("mail", "alice@example.com").
			With("objectClass", "inetOrgPerson"),
	)

	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),
		ldapauth.WithEmailAttribute("mail"),
	)
	if err != nil {
		fmt.Println(err)

		return
	}
	defer auth.Close()

	identity, err := auth.Authenticate(context.Background(), "alice", "s3cret")
	if err != nil {
		fmt.Println(err)

		return
	}

	fmt.Println(identity.GetEmail())
	// Output: alice@example.com
}

// What went to the directory, which is usually the thing a security test
// wants to assert on.
func ExampleDirectory_Filters() {
	dir := ldaptest.New(
		ldaptest.User("uid=alice,ou=people,dc=example,dc=com", "s3cret").
			With("uid", "alice").
			With("objectClass", "inetOrgPerson"),
		ldaptest.User("cn=svc,dc=example,dc=com", "svc-password").
			With("objectClass", "person"),
	)

	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithServiceAccount("cn=svc,dc=example,dc=com", "svc-password"),
		ldapauth.WithUserSearch("ou=people,dc=example,dc=com", "(uid={{username}})"),
	)
	if err != nil {
		fmt.Println(err)

		return
	}
	defer auth.Close()

	// A username that is trying something.
	_, _ = auth.Authenticate(context.Background(), "*)(uid=*", "anything")

	fmt.Println(dir.Filters()[0])
	// Output: (uid=\2a\29\28uid=\2a)
}

// The empty-password bind is modelled faithfully: a conforming server
// answers it with success, which is why a library that sends one is a
// library that authenticates anybody.
func ExampleDirectory_Binds() {
	dir := ldaptest.New(
		ldaptest.User("uid=alice,ou=people,dc=example,dc=com", "s3cret").
			With("uid", "alice").
			With("objectClass", "inetOrgPerson"),
	)

	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),
	)
	if err != nil {
		fmt.Println(err)

		return
	}
	defer auth.Close()

	_, err = auth.Authenticate(context.Background(), "alice", "")

	fmt.Println(errors.Is(err, ldapauth.ErrEmptyPassword))
	fmt.Println("binds reaching the directory:", len(dir.Binds()))
	// Output:
	// true
	// binds reaching the directory: 0
}

// Taking a server away, which is what a failover test needs. Connections
// already open to it break, as they would.
func ExampleDirectory_SetDown() {
	dir := ldaptest.New(
		ldaptest.User("uid=alice,ou=people,dc=example,dc=com", "s3cret").
			With("uid", "alice").
			With("objectClass", "inetOrgPerson"),
	)

	dir.SetDown("ldap://dc1", true)

	auth, err := ldapauth.New(
		ldapauth.WithURLs("ldap://dc1", "ldap://dc2"),
		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),
	)
	if err != nil {
		fmt.Println(err)

		return
	}
	defer auth.Close()

	if _, err := auth.Authenticate(context.Background(), "alice", "s3cret"); err != nil {
		fmt.Println(err)

		return
	}

	fmt.Println("bound on", dir.Binds()[0].URL)
	// Output: bound on ldap://dc2
}
