// Command basic authenticates one username and password with the
// direct-bind strategy, which needs no service account.
//
//	go run ./examples/basic -url ldaps://dc1.corp.example:636 \
//	    -bind-dn 'uid={{username}},ou=people,dc=corp,dc=example' \
//	    -username alice
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

func main() {
	var (
		url      = flag.String("url", "ldaps://localhost:636", "directory URL")
		bindDN   = flag.String("bind-dn", "uid={{username}},ou=people,dc=example,dc=com", "bind DN template")
		username = flag.String("username", "", "username to authenticate")
		insecure = flag.Bool("insecure", false, "skip certificate verification (development only)")
	)

	flag.Parse()

	if *username == "" {
		fmt.Fprintln(os.Stderr, "a -username is required")
		os.Exit(2)
	}

	password, err := readPassword()
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading password:", err)
		os.Exit(1)
	}

	opts := []ldapauth.Option{
		ldapauth.WithURL(*url),
		ldapauth.WithDirectBind(*bindDN),
		ldapauth.WithDisplayNameAttribute("cn"),
		ldapauth.WithEmailAttribute("mail"),
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

	principal, err := auth.Authenticate(ctx, *username, password)

	switch {
	case err == nil:
		fmt.Printf("authenticated\n  dn:    %s\n  name:  %s\n  email: %s\n",
			principal.DN, principal.DisplayName, principal.Email)

	case errors.Is(err, ldapauth.ErrInvalidCredentials):
		fmt.Fprintln(os.Stderr, "rejected")
		os.Exit(1)

	default:
		fmt.Fprintln(os.Stderr, "failed:", err)
		os.Exit(1)
	}
}

// readPassword reads from standard input. A real program would use a
// terminal package to turn echo off; this one keeps its dependency list at
// zero and says so.
func readPassword() (string, error) {
	fmt.Fprint(os.Stderr, "password (echoed): ")

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimRight(line, "\r\n"), nil
}
