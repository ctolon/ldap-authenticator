// Command escaping shows what LDAP injection looks like, what the usual
// fix looks like, and what this package does instead.
//
//	go run ./examples/escaping
//
// The usual fix is right, and it is what this package uses underneath:
//
//	safe := ldap.EscapeFilter(rawUsername)
//	filter := fmt.Sprintf("(&(objectClass=person)(uid=%s))", safe)
//
// What a Sprintf cannot do is stop the next person from writing the line
// without the EscapeFilter, or from escaping a value for the wrong grammar
// — a filter value and a DN component need different escaping, and using
// one where the other belongs is a bug that looks correct. So the package
// parses the template once, at startup, and escapes each placeholder for
// the grammar it lands in. There is no exported way to interpolate an
// unescaped value.
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const (
	peopleDN = "ou=people,dc=example,dc=com"
	adminsDN = "ou=admins,dc=example,dc=com"
)

// unsafeFilter is the bug: a username concatenated into a filter.
func unsafeFilter(username string) string {
	return fmt.Sprintf("(&(objectClass=person)(uid=%s))", username)
}

// safeFilter is the usual fix, and what this package does underneath.
func safeFilter(username string) string {
	return fmt.Sprintf("(&(objectClass=person)(uid=%s))", ldap.EscapeFilter(username))
}

// unsafeDN is the same bug in the other grammar. Note that escaping for a
// filter would not help here: a filter escape leaves the comma alone, and
// the comma is what adds a component to a DN.
func unsafeDN(username string) string {
	return "uid=" + username + "," + peopleDN
}

func safeDN(username string) string {
	return "uid=" + ldap.EscapeDN(username) + "," + peopleDN
}

func main() {
	hostile := []string{
		"alice",
		"*",
		"*)(uid=*",
		"alice)(|(uid=*",
		"admin,ou=admins,dc=example,dc=com",
	}

	fmt.Println("== filters ==")
	fmt.Println()

	for _, username := range hostile {
		fmt.Printf("username   %q\n", username)
		fmt.Printf("  unsafe   %s\n", unsafeFilter(username))
		fmt.Printf("  escaped  %s\n", safeFilter(username))
		fmt.Println()
	}

	fmt.Println("== distinguished names ==")
	fmt.Println()

	for _, username := range hostile {
		dn := unsafeDN(username)
		components := "unparseable"

		if parsed, err := ldap.ParseDN(dn); err == nil {
			components = fmt.Sprintf("%d components", len(parsed.RDNs))
		}

		fmt.Printf("username   %q\n", username)
		fmt.Printf("  unsafe   %s   (%s)\n", dn, components)
		fmt.Printf("  escaped  %s\n", safeDN(username))
		fmt.Println()
	}

	fmt.Println("== what the package sends ==")
	fmt.Println()

	demonstrate(hostile)
}

// demonstrate runs the real thing against an in-memory directory holding
// an admin entry that a DN injection would be trying to reach, and prints
// what actually went to the directory.
func demonstrate(hostile []string) {
	dir := ldaptest.New(
		ldaptest.User("uid=alice,"+peopleDN, "s3cret").
			With("uid", "alice").
			With("objectClass", "person"),

		ldaptest.User("uid=root,"+adminsDN, "root-password").
			With("uid", "root").
			With("objectClass", "person"),

		ldaptest.User("cn=svc,dc=example,dc=com", "svc-password").
			With("objectClass", "person"),
	)

	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithServiceAccount("cn=svc,dc=example,dc=com", "svc-password"),
		ldapauth.WithUserSearch(peopleDN, "(&(objectClass=person)(uid={{username}}))"),
	)
	if err != nil {
		fmt.Println("configuration:", err)

		return
	}

	defer func() { _ = auth.Close() }()

	for _, username := range hostile {
		// Every one of these is a login attempt with the right password
		// for the admin account. None of them reaches it.
		_, _ = auth.Authenticate(context.Background(), username, "root-password")
	}

	for i, filter := range dir.Filters() {
		if i >= len(hostile) {
			break
		}

		fmt.Printf("username   %q\n", hostile[i])
		fmt.Printf("  filter   %s\n", filter)
		fmt.Println()
	}

	fmt.Println("bind DNs the directory was asked about:")

	for _, bind := range dir.Binds() {
		if strings.HasSuffix(bind.DN, adminsDN) {
			fmt.Println("  LEAKED:", bind.DN)

			continue
		}

		fmt.Println(" ", bind.DN)
	}
}
