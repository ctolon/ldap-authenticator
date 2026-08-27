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

	fmt.Println(principal.GetDN())
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

	fmt.Println(principal.GetDisplayName(), principal.GetEmail())
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

	fmt.Println(principal.GetGroups(), principal.InGroup("developers"))
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

		fmt.Fprintln(w, "hello", principal.GetUsername())
	}

	_ = handler
}

// A custom mapper produces the application's own user type. Everything
// downstream keeps working because it depends on [ldapauth.Identity]
// rather than on the concrete type.
func ExampleWithPrincipalMapper() {
	auth, err := ldapauth.New(
		ldapauth.WithURL("ldaps://dc1.example.com:636"),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),
		ldapauth.WithAttributes("mail"),

		ldapauth.WithPrincipalMapper(ldapauth.PrincipalMapperFunc(
			func(m ldapauth.Mapping) (ldapauth.Identity, error) {
				// Principal.Extra is for the common case: a type of your
				// own is only needed when you want your own methods.
				return &ldapauth.Principal{
					DN:       m.DN,
					Username: m.Username,
					Groups:   m.Groups,
					Extra:    tenantFor(m.Username),
				}, nil
			},
		)),

		ldapauth.WithDialer(exampleDirectory().Dialer()),
	)
	if err != nil {
		fmt.Println("configuration:", err)

		return
	}
	defer auth.Close()

	identity, err := auth.Authenticate(context.Background(), "alice", "s3cret")
	if err != nil {
		fmt.Println("authentication:", err)

		return
	}

	principal, _ := ldapauth.AsPrincipal(identity)

	fmt.Println(principal.Username, principal.Extra)
	// Output: alice acme
}

func tenantFor(string) string { return "acme" }

// A custom resolver takes groups from somewhere the directory is not. It
// replaces the built-in resolution rather than adding to it, so one that
// wants both should ask the directory itself through [ldapauth.GroupRequest].
func ExampleWithGroupResolver() {
	auth, err := ldapauth.New(
		ldapauth.WithURL("ldaps://dc1.example.com:636"),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),

		ldapauth.WithGroupResolver(ldapauth.GroupResolverFunc(
			func(_ context.Context, request ldapauth.GroupRequest) ([]string, error) {
				return rolesFor(request.DN), nil
			},
		)),

		ldapauth.WithDialer(exampleDirectory().Dialer()),
	)
	if err != nil {
		fmt.Println("configuration:", err)

		return
	}
	defer auth.Close()

	identity, err := auth.Authenticate(context.Background(), "alice", "s3cret")
	if err != nil {
		fmt.Println("authentication:", err)

		return
	}

	fmt.Println(identity.GetGroups())
	// Output: [billing:read billing:write]
}

func rolesFor(string) []string { return []string{"billing:read", "billing:write"} }

// Reading an identity without a password, for when authentication happened
// somewhere else — a SAML assertion, an OIDC token, an authenticating
// proxy. Unlike Authenticate, this distinguishes a missing user: the
// caller already knows who they are asking about.
func ExampleClient_Lookup() {
	auth, err := ldapauth.New(
		ldapauth.WithURL("ldaps://dc1.example.com:636"),
		ldapauth.WithServiceAccount("cn=readonly,dc=example,dc=com", "service-password"),
		ldapauth.WithUserSearch("ou=people,dc=example,dc=com", "(uid={{username}})"),
		ldapauth.WithEmailAttribute("mail"),

		ldapauth.WithDialer(exampleDirectory().Dialer()),
	)
	if err != nil {
		fmt.Println("configuration:", err)

		return
	}
	defer auth.Close()

	identity, err := auth.Lookup(context.Background(), "alice")
	if err != nil {
		fmt.Println("lookup:", err)

		return
	}

	fmt.Println(identity.GetEmail())

	if _, err := auth.Lookup(context.Background(), "nobody"); errors.Is(err, ldapauth.ErrUserNotFound) {
		fmt.Println("nobody is not in the directory")
	}
	// Output:
	// alice@example.com
	// nobody is not in the directory
}

// Depending on the interface rather than the type is what lets a
// deployment wrap the real authenticator — with a circuit breaker, a
// second directory, or a local account for the break-glass user — without
// anything downstream knowing.
func ExampleAuthenticator() {
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

	// Embedding the interface means a method added to Authenticator in a
	// later release passes straight through rather than breaking this.
	var wrapped ldapauth.Authenticator = breakGlass{Authenticator: auth}

	for _, username := range []string{"alice", "root"} {
		identity, err := wrapped.Authenticate(context.Background(), username, "s3cret")
		if err != nil {
			fmt.Println(username, "rejected")

			continue
		}

		fmt.Println(username, "->", identity.GetDN())
	}
	// Output:
	// alice -> uid=alice,ou=people,dc=example,dc=com
	// root -> local:root
}

type breakGlass struct {
	ldapauth.Authenticator
}

func (b breakGlass) Authenticate(
	ctx context.Context,
	username, password string,
) (ldapauth.Identity, error) {
	if username == "root" && password == "s3cret" {
		return &ldapauth.Principal{DN: "local:root", Username: "root", Groups: []string{"admin"}}, nil
	}

	return b.Authenticator.Authenticate(ctx, username, password)
}
