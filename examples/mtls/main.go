// Command mtls connects to a directory that authenticates the application
// itself with a client certificate, on top of authenticating the user with
// a bind.
//
//	go run ./examples/mtls \
//	    -url ldaps://dc1.corp.example:636 \
//	    -ca /etc/ssl/certs/corp-ca.pem \
//	    -cert /etc/ssl/certs/app.pem -key /etc/ssl/private/app.key \
//	    -username alice -password s3cret
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

func main() {
	var (
		url      = flag.String("url", "ldaps://localhost:636", "directory URL")
		ca       = flag.String("ca", "", "PEM file holding the CA that signed the directory's certificate")
		cert     = flag.String("cert", "", "PEM file holding this application's certificate")
		key      = flag.String("key", "", "PEM file holding this application's private key")
		server   = flag.String("server-name", "", "name to verify against the certificate, if not the one in -url")
		username = flag.String("username", "", "username to authenticate")
		password = flag.String("password", "", "password to verify")
	)

	flag.Parse()

	opts := []ldapauth.Option{
		ldapauth.WithURL(*url),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),

		// TLS 1.3 only. The directory either supports it or it is old
		// enough that its LDAP is not the first thing to worry about.
		ldapauth.WithMinTLSVersion(tls.VersionTLS13),
	}

	if *ca != "" {
		opts = append(opts, ldapauth.WithRootCAFile(*ca))
	}

	if *cert != "" || *key != "" {
		opts = append(opts, ldapauth.WithClientCertificateFiles(*cert, *key))
	}

	if *server != "" {
		opts = append(opts, ldapauth.WithServerName(*server))
	}

	auth, err := ldapauth.New(opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}

	defer func() { _ = auth.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := auth.Authenticate(ctx, *username, *password); err != nil {
		fmt.Fprintln(os.Stderr, "failed:", err)
		os.Exit(1)
	}

	fmt.Println("authenticated over mutual TLS")
}
