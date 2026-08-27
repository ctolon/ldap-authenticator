package httpauth_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/httpauth"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

// exampleAuth builds an authenticator against an in-memory directory, so
// that the examples run with no LDAP server anywhere.
func exampleAuth() *ldapauth.Client {
	dir := ldaptest.New(
		ldaptest.User("uid=alice,ou=people,dc=example,dc=com", "s3cret").
			With("uid", "alice").
			With("cn", "Alice Example").
			With("objectClass", "inetOrgPerson").
			With("memberOf", "cn=developers,ou=groups,dc=example,dc=com"),

		ldaptest.Group("cn=developers,ou=groups,dc=example,dc=com").With("cn", "developers"),
	)

	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),
		ldapauth.WithMemberOfGroups(),
	)
	if err != nil {
		panic(err)
	}

	return auth
}

// The middleware has the func(http.Handler) http.Handler shape that chi,
// gorilla/mux, and a bare ServeMux all expect.
func ExampleBasicAuth() {
	auth := exampleAuth()
	defer auth.Close()

	private := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := httpauth.MustIdentity(r.Context())

		fmt.Fprintf(w, "hello %s", identity.GetUsername())
	})

	handler := httpauth.BasicAuth(auth,
		httpauth.WithRealm("corp"),
		httpauth.RequireAnyGroup("developers"),
		httpauth.WithMinimumDuration(10*time.Millisecond),
	)(private)

	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	request.SetBasicAuth("alice", "s3cret")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	fmt.Println(recorder.Code, recorder.Body)
	// Output: 200 hello alice
}

// A request with no credentials gets a challenge, and one with the wrong
// credentials gets a bare 401: a rejection that explains itself is a
// rejection that helps somebody guess.
func ExampleBasicAuth_rejection() {
	auth := exampleAuth()
	defer auth.Close()

	handler := httpauth.BasicAuth(auth, httpauth.WithRealm("corp"))(http.NotFoundHandler())

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/private", nil))

	fmt.Println(recorder.Code)
	fmt.Println(recorder.Header().Get("WWW-Authenticate"))
	fmt.Printf("body: %q\n", recorder.Body.String())
	// Output:
	// 401
	// Basic realm="corp", charset="UTF-8"
	// body: ""
}

// Valid credentials that are not in a required group are a 403 rather than
// a 401. The distinction matters to a client: 401 says try other
// credentials, 403 says do not bother.
func ExampleRequireAnyGroup() {
	auth := exampleAuth()
	defer auth.Close()

	handler := httpauth.BasicAuth(auth, httpauth.RequireAnyGroup("ops"))(http.NotFoundHandler())

	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	request.SetBasicAuth("alice", "s3cret")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	fmt.Println(recorder.Code)
	// Output: 403
}

// LoginHandler reads credentials from a JSON body, a form body, or a Basic
// header, and hands you the identity. What happens next is your
// application's decision: this package issues no session and no token.
func ExampleLoginHandler() {
	auth := exampleAuth()
	defer auth.Close()

	handler := httpauth.LoginHandler(auth,
		func(w http.ResponseWriter, r *http.Request, identity ldapauth.Identity) {
			// Where a real application would start a session.
			w.Header().Set("Content-Type", "application/json")

			_ = json.NewEncoder(w).Encode(map[string]any{
				"dn":     identity.GetDN(),
				"groups": identity.GetGroups(),
			})
		},
	)

	body := `{"username":"alice","password":"s3cret"}`
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	fmt.Print(recorder.Body.String())
	// Output: {"dn":"uid=alice,ou=people,dc=example,dc=com","groups":["developers"]}
}

// Replacing the rejection with your own shape. Write a response, and do
// not write the error: its text can name the account.
func ExampleWithErrorHandler() {
	auth := exampleAuth()
	defer auth.Close()

	handler := httpauth.BasicAuth(auth,
		httpauth.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
			status := httpauth.Status(err)

			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(status)

			_ = json.NewEncoder(w).Encode(map[string]any{
				"title":  http.StatusText(status),
				"status": status,
			})
		}),
	)(http.NotFoundHandler())

	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	request.SetBasicAuth("alice", "wrong")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	fmt.Print(recorder.Body.String())
	// Output: {"status":401,"title":"Unauthorized"}
}

// A handler behind the middleware needs no directory to test: put an
// identity in the context directly.
func ExampleWithIdentity() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := httpauth.MustIdentity(r.Context())

		fmt.Println(identity.GetUsername(), identity.InGroup("developers"))
	})

	request := httptest.NewRequest(http.MethodGet, "/private", nil)

	request = request.WithContext(httpauth.WithIdentity(request.Context(), &ldapauth.Principal{
		Username: "alice",
		Groups:   []string{"developers"},
	}))

	handler.ServeHTTP(httptest.NewRecorder(), request)
	// Output: alice true
}
