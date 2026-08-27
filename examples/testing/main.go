// Command testing runs the whole library against the in-memory directory
// in the ldaptest package, so you can see what a login does without having
// an LDAP server anywhere.
//
//	go run ./examples/testing
//
// The same directory is what the library's own tests use, and what your
// tests can use: point an authenticator at it with WithDialer and there is
// no server to start, no container to wait for, and no fixture to reset.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

func main() {
	dir := ldaptest.New(
		ldaptest.User("uid=alice,ou=people,dc=example,dc=com", "s3cret").
			With("uid", "alice").
			With("cn", "Alice Example").
			With("mail", "alice@example.com").
			With("objectClass", "inetOrgPerson").
			With("memberOf", "cn=developers,ou=groups,dc=example,dc=com"),

		ldaptest.Group("cn=developers,ou=groups,dc=example,dc=com").
			With("cn", "developers").
			With("objectClass", "groupOfNames").
			With("memberOf", "cn=staff,ou=groups,dc=example,dc=com"),

		ldaptest.Group("cn=staff,ou=groups,dc=example,dc=com").
			With("cn", "staff").
			With("objectClass", "groupOfNames"),
	)

	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithNestedGroups(),
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}

	defer func() { _ = auth.Close() }()

	attempts := []struct {
		username, password, expect string
	}{
		{"alice", "s3cret", "authenticated"},
		{"alice", "wrong", "rejected"},
		{"alice", "", "rejected before any bind"},
		{"*)(uid=*", "anything", "rejected, and the filter was escaped"},
		{"nobody", "anything", "rejected, indistinguishably from a wrong password"},
	}

	for _, attempt := range attempts {
		identity, err := auth.Authenticate(context.Background(), attempt.username, attempt.password)

		switch {
		case err == nil:
			fmt.Printf("%-12q %-40s groups=%v\n", attempt.username, attempt.expect, identity.GetGroups())
		case errors.Is(err, ldapauth.ErrInvalidCredentials), errors.Is(err, ldapauth.ErrEmptyPassword):
			fmt.Printf("%-12q %-40s (%v)\n", attempt.username, attempt.expect, err)
		default:
			fmt.Printf("%-12q unexpected: %v\n", attempt.username, err)
		}
	}

	fmt.Println()
	fmt.Println("filters the directory saw:")

	for _, filter := range dir.Filters() {
		fmt.Println(" ", filter)
	}
}
