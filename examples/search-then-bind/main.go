// Command search-then-bind authenticates with a service account: it
// searches for the user's entry, then verifies the password by binding as
// the DN the search returned.
//
//	LDAP_SERVICE_PASSWORD=... go run ./examples/search-then-bind \
//	    -url ldaps://dc1.corp.example:636 \
//	    -service-dn 'cn=readonly,dc=corp,dc=example' \
//	    -base-dn 'ou=people,dc=corp,dc=example' \
//	    -username alice -password s3cret
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

func main() {
	var (
		url       = flag.String("url", "ldaps://localhost:636", "directory URL")
		serviceDN = flag.String("service-dn", "cn=readonly,dc=example,dc=com", "service account DN")
		baseDN    = flag.String("base-dn", "ou=people,dc=example,dc=com", "where users live")
		filter    = flag.String("filter", "(&(objectClass=inetOrgPerson)(uid={{username}}))", "user filter")
		username  = flag.String("username", "", "username to authenticate")
		password  = flag.String("password", "", "password to verify")
		insecure  = flag.Bool("insecure", false, "skip certificate verification (development only)")
	)

	flag.Parse()

	servicePassword := os.Getenv("LDAP_SERVICE_PASSWORD")
	if servicePassword == "" {
		fmt.Fprintln(os.Stderr, "LDAP_SERVICE_PASSWORD is not set")
		os.Exit(2)
	}

	opts := []ldapauth.Option{
		ldapauth.WithURL(*url),
		ldapauth.WithServiceAccount(*serviceDN, servicePassword),
		ldapauth.WithUserSearch(*baseDN, *filter),
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithDisplayNameAttribute("cn"),

		// The pool holds the service identity. The user's bind always
		// gets a connection of its own.
		ldapauth.WithPoolSize(8),
		ldapauth.WithPoolMinIdle(1),
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

	if err := auth.HealthCheck(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "directory unreachable:", err)
		os.Exit(1)
	}

	identity, err := auth.Authenticate(ctx, *username, *password)
	if err != nil {
		if errors.Is(err, ldapauth.ErrInvalidCredentials) {
			fmt.Fprintln(os.Stderr, "rejected")
			os.Exit(1)
		}

		fmt.Fprintln(os.Stderr, "failed:", err)
		os.Exit(1)
	}

	fmt.Printf("authenticated %s (%s)\n", identity.GetDN(), identity.GetEmail())
	fmt.Printf("pool: %+v\n", auth.Stats(ctx))
}
