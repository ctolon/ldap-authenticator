// Command groups shows the three ways group membership can be resolved,
// against whichever the directory supports.
//
//	go run ./examples/groups -mode memberof -username alice -password s3cret
//	go run ./examples/groups -mode search   -username alice -password s3cret
//	go run ./examples/groups -mode ad       -username alice -password s3cret
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

func main() {
	var (
		url      = flag.String("url", "ldaps://localhost:636", "directory URL")
		baseDN   = flag.String("base-dn", "ou=people,dc=example,dc=com", "where users live")
		groupDN  = flag.String("group-dn", "ou=groups,dc=example,dc=com", "where groups live")
		mode     = flag.String("mode", "memberof", "memberof, search, or ad")
		nested   = flag.Bool("nested", true, "expand groups that are members of groups")
		username = flag.String("username", "", "username to authenticate")
		password = flag.String("password", "", "password to verify")
		insecure = flag.Bool("insecure", false, "skip certificate verification (development only)")
	)

	flag.Parse()

	opts := []ldapauth.Option{
		ldapauth.WithURL(*url),
		ldapauth.WithServiceAccount("cn=readonly,dc=example,dc=com", os.Getenv("LDAP_SERVICE_PASSWORD")),
		ldapauth.WithUserSearch(*baseDN, "(uid={{username}})"),
	}

	switch *mode {
	case "memberof":
		// Free: the memberships come back with the user's entry. Needs a
		// directory that maintains the attribute.
		opts = append(opts, ldapauth.WithMemberOfGroups())

	case "search":
		// One search. Works anywhere, including directories where
		// membership lives only on the group.
		opts = append(opts, ldapauth.WithGroupSearch(*groupDN,
			"(&(objectClass=groupOfNames)(member={{user_dn}}))"))

	case "ad":
		// One search, transitive, computed by the server. Active
		// Directory only — anything else answers with no entries, which
		// looks exactly like a user in no groups.
		opts = append(opts, ldapauth.WithActiveDirectoryGroups(*groupDN))

	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(2)
	}

	if *nested && *mode != "ad" {
		opts = append(opts, ldapauth.WithNestedGroups())
	}

	if *insecure {
		opts = append(opts, ldapauth.WithInsecureSkipVerify())
	}

	auth, err := ldapauth.New(opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}

	defer func() { _ = auth.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	identity, err := auth.Authenticate(ctx, *username, *password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed:", err)
		os.Exit(1)
	}

	groups := identity.GetGroups()

	fmt.Printf("%s is in %d groups:\n", identity.GetDN(), len(groups))

	for _, group := range groups {
		fmt.Println(" ", group)
	}
}
