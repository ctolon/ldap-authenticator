// Command lookup reads a user's attributes and groups without a password,
// for the case where authentication already happened somewhere else.
//
//	go run ./examples/lookup
//
// A SAML assertion, an OIDC token, mTLS at the edge, or an authenticating
// reverse proxy has established who somebody is. The directory is still
// where their attributes and groups live, and Lookup is how to ask.
//
// The difference from Authenticate is worth stating: Lookup returns
// ErrUserNotFound for a missing user rather than collapsing it into
// ErrInvalidCredentials. There is no account-enumeration oracle to protect
// here — the caller has already been told who they are asking about.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/httpauth"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const (
	peopleDN = "ou=people,dc=example,dc=com"
	groupsDN = "ou=groups,dc=example,dc=com"
)

func main() {
	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(directory().Dialer()),

		// Lookup needs a service account: there is no user bind to
		// borrow a connection from.
		ldapauth.WithServiceAccount("cn=svc,dc=example,dc=com", "svc-password"),
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithDisplayNameAttribute("cn"),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}

	defer func() { _ = auth.Close() }()

	ctx := context.Background()

	for _, username := range []string{"alice", "nobody"} {
		identity, err := auth.Lookup(ctx, username)

		switch {
		case err == nil:
			fmt.Printf("%-8s %s <%s> in %v\n",
				username, identity.GetDisplayName(), identity.GetEmail(), identity.GetGroups())

		case errors.Is(err, ldapauth.ErrUserNotFound):
			fmt.Printf("%-8s not in the directory\n", username)

		default:
			fmt.Printf("%-8s lookup failed: %v\n", username, err)
		}
	}

	fmt.Println()
	fmt.Println("as middleware behind a trusted proxy:")
	fmt.Println()

	demonstrateProxy(auth)
}

// trustedHeaderAuth turns a header set by an authenticating proxy into an
// identity from the directory.
//
// The header has to be trustworthy, and that is the whole of the security
// of this arrangement. A proxy that forwards a client-supplied
// X-Remote-User unchanged is a proxy that lets anybody be anybody, so the
// proxy must strip the header from the inbound request and set it itself,
// and this handler must not be reachable except through the proxy.
func trustedHeaderAuth(auth ldapauth.Authenticator, header string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username := strings.TrimSpace(r.Header.Get(header))
			if username == "" {
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			identity, err := auth.Lookup(ctx, username)
			if err != nil {
				if errors.Is(err, ldapauth.ErrUserNotFound) {
					// The proxy authenticated somebody the directory
					// does not have. That is a provisioning problem, and
					// it is a 403 rather than a 401: retrying with other
					// credentials will not help.
					w.WriteHeader(http.StatusForbidden)

					return
				}

				w.WriteHeader(http.StatusServiceUnavailable)

				return
			}

			// The identity goes into the request context exactly where
			// httpauth.BasicAuth would have put it, so handlers and any
			// middleware downstream cannot tell the difference.
			next.ServeHTTP(w, r.WithContext(httpauth.WithIdentity(r.Context(), identity)))
		})
	}
}

func demonstrateProxy(auth ldapauth.Authenticator) {
	handler := trustedHeaderAuth(auth, "X-Remote-User")(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			identity := httpauth.MustIdentity(r.Context())

			fmt.Fprintf(w, "%s in %v", identity.GetDN(), identity.GetGroups())
		},
	))

	for _, username := range []string{"alice", "nobody", ""} {
		request, _ := http.NewRequest(http.MethodGet, "/private", nil)

		if username != "" {
			request.Header.Set("X-Remote-User", username)
		}

		recorder := &recordingWriter{header: http.Header{}}
		handler.ServeHTTP(recorder, request)

		fmt.Printf("  X-Remote-User: %-8q -> %d %s\n", username, recorder.status, recorder.body)
	}
}

// recordingWriter is httptest.ResponseRecorder, without importing the
// testing tree into a command.
type recordingWriter struct {
	header http.Header
	status int
	body   string
}

func (w *recordingWriter) Header() http.Header { return w.header }

func (w *recordingWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	w.body += string(p)

	return len(p), nil
}

func (w *recordingWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func directory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User("uid=alice,"+peopleDN, "s3cret").
			With("uid", "alice").
			With("cn", "Alice Example").
			With("mail", "alice@example.com").
			With("objectClass", "inetOrgPerson").
			With("memberOf", "cn=developers,"+groupsDN),

		ldaptest.User("cn=svc,dc=example,dc=com", "svc-password").
			With("objectClass", "person"),

		ldaptest.Group("cn=developers,"+groupsDN).With("cn", "developers"),
	)
}
