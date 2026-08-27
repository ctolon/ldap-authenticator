package ldapauth_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

// exampleDirectory is the in-memory directory the examples run against, so
// that they are compiled and executed rather than merely displayed.
func exampleDirectory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User("uid=alice,ou=people,dc=example,dc=com", "s3cret").
			With("uid", "alice").
			With("cn", "Alice Example").
			With("mail", "alice@example.com").
			With("objectClass", "inetOrgPerson").
			With("memberOf", "cn=developers,ou=groups,dc=example,dc=com"),

		ldaptest.User("cn=readonly,dc=example,dc=com", "service-password").
			With("objectClass", "person"),

		ldaptest.Group("cn=developers,ou=groups,dc=example,dc=com").
			With("cn", "developers").
			With("objectClass", "groupOfNames").
			With("member", "uid=alice,ou=people,dc=example,dc=com"),
	)
}

// The direct-bind strategy: the DN is derived from the username, so a
// login is one round trip and no privileged account is needed anywhere.
func Example_directBind() {
	auth, err := ldapauth.New(
		ldapauth.WithURL("ldaps://dc1.example.com:636"),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),

		// The example talks to an in-memory directory instead of the URL
		// above; a real program leaves this out.
		ldapauth.WithDialer(exampleDirectory().Dialer()),
	)
	if err != nil {
		fmt.Println("configuration:", err)

		return
	}
	defer auth.Close()

	principal, err := auth.Authenticate(context.Background(), "alice", "s3cret")
	if err != nil {
		fmt.Println("authentication:", err)

		return
	}

	fmt.Println(principal.DN)
	// Output: uid=alice,ou=people,dc=example,dc=com
}

// The search-then-bind strategy: a service account finds the user, and the
// password is verified by binding as the DN the search returned.
func Example_searchThenBind() {
	auth, err := ldapauth.New(
		ldapauth.WithURL("ldaps://dc1.example.com:636"),
		ldapauth.WithServiceAccount("cn=readonly,dc=example,dc=com", "service-password"),
		ldapauth.WithUserSearch(
			"ou=people,dc=example,dc=com",
			"(&(objectClass=inetOrgPerson)(uid={{username}}))",
		),
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithDisplayNameAttribute("cn"),

		ldapauth.WithDialer(exampleDirectory().Dialer()),
	)
	if err != nil {
		fmt.Println("configuration:", err)

		return
	}
	defer auth.Close()

	principal, err := auth.Authenticate(context.Background(), "alice", "s3cret")
	if err != nil {
		fmt.Println("authentication:", err)

		return
	}

	fmt.Println(principal.DisplayName, principal.Email)
	// Output: Alice Example alice@example.com
}

// Group membership, read off the user's own entry.
func Example_groups() {
	auth, err := ldapauth.New(
		ldapauth.WithURL("ldaps://dc1.example.com:636"),
		ldapauth.WithServiceAccount("cn=readonly,dc=example,dc=com", "service-password"),
		ldapauth.WithUserSearch("ou=people,dc=example,dc=com", "(uid={{username}})"),
		ldapauth.WithMemberOfGroups(),

		ldapauth.WithDialer(exampleDirectory().Dialer()),
	)
	if err != nil {
		fmt.Println("configuration:", err)

		return
	}
	defer auth.Close()

	principal, err := auth.Authenticate(context.Background(), "alice", "s3cret")
	if err != nil {
		fmt.Println("authentication:", err)

		return
	}

	fmt.Println(principal.Groups, principal.InGroup("developers"))
	// Output: [developers] true
}

// Telling the two kinds of failure apart is the whole of the error
// handling most callers need: a rejected credential is the user's problem,
// and anything else is yours.
func Example_errorHandling() {
	auth, err := ldapauth.New(
		ldapauth.WithURL("ldaps://dc1.example.com:636"),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),

		ldapauth.WithDialer(exampleDirectory().Dialer()),
	)
	if err != nil {
		fmt.Println("configuration:", err)

		return
	}
	defer auth.Close()

	_, err = auth.Authenticate(context.Background(), "alice", "wrong-password")

	switch {
	case err == nil:
		fmt.Println("authenticated")
	case errors.Is(err, ldapauth.ErrInvalidCredentials):
		fmt.Println("401")
	case errors.Is(err, ldapauth.ErrEmptyPassword):
		fmt.Println("400")
	default:
		fmt.Println("503")
	}
	// Output: 401
}

// A production configuration, with everything the defaults leave to you.
func ExampleNew_production() {
	auth, err := ldapauth.New(
		ldapauth.WithURLs(
			"ldaps://dc1.example.com:636",
			"ldaps://dc2.example.com:636",
		),
		ldapauth.WithRootCAFile("/etc/ssl/certs/corp-ca.pem"),
		ldapauth.WithServiceAccount(
			"cn=readonly,dc=example,dc=com",
			os.Getenv("LDAP_SERVICE_PASSWORD"),
		),
		ldapauth.WithUserSearch("ou=people,dc=example,dc=com", "(uid={{username}})"),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithEmailAttribute("mail"),

		ldapauth.WithDialTimeout(3*time.Second),
		ldapauth.WithRequestTimeout(10*time.Second),
		ldapauth.WithPoolSize(16),
		ldapauth.WithPoolMinIdle(2),
		ldapauth.WithRetry(2),
		ldapauth.WithLogger(slog.Default()),
	)
	if err != nil {
		// A configuration error here is a startup failure, and that is
		// the point: it is far better than a failed login at 3am.
		fmt.Println("configuration:", err)

		return
	}
	defer auth.Close()

	if err := auth.HealthCheck(context.Background()); err != nil {
		fmt.Println("directory unreachable:", err)
	}
}

// Wiring the authenticator to an HTTP handler by hand. The contrib modules
// do this for you, for net/http, Gin, Echo, and Fiber.
func ExampleAuthenticator_Authenticate_httpBasic() {
	auth, err := ldapauth.New(
		ldapauth.WithURL("ldaps://dc1.example.com:636"),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),

		ldapauth.WithDialer(exampleDirectory().Dialer()),
	)
	if err != nil {
		fmt.Println("configuration:", err)

		return
	}
	defer auth.Close()

	handler := func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="example"`)
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		principal, err := auth.Authenticate(r.Context(), username, password)
		if err != nil {
			if errors.Is(err, ldapauth.ErrInvalidCredentials) {
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			w.WriteHeader(http.StatusServiceUnavailable)

			return
		}

		fmt.Fprintln(w, "hello", principal.Username)
	}

	_ = handler
}
