package httpauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/httpauth"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const (
	peopleDN = "ou=people,dc=example,dc=com"
	groupsDN = "ou=groups,dc=example,dc=com"
	aliceDN  = "uid=alice," + peopleDN
	bobDN    = "uid=bob," + peopleDN
	devsDN   = "cn=devs," + groupsDN
	opsDN    = "cn=ops," + groupsDN
)

func newAuth(t *testing.T, opts ...ldapauth.Option) *ldapauth.Authenticator {
	t.Helper()

	dir := ldaptest.New(
		ldaptest.User(aliceDN, "alice-pw").
			With("uid", "alice").
			With("objectClass", "inetOrgPerson").
			With("memberOf", devsDN),
		ldaptest.User(bobDN, "bob-pw").
			With("uid", "bob").
			With("objectClass", "inetOrgPerson"),
		ldaptest.Group(devsDN).With("cn", "devs"),
		ldaptest.Group(opsDN).With("cn", "ops"),
	)

	base := []ldapauth.Option{
		ldapauth.WithURL("ldap://memory"),
		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithDirectBind("uid={{username}}," + peopleDN),
	}

	auth, err := ldapauth.New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() { _ = auth.Close() })

	return auth
}

// echoPrincipal writes the authenticated username, so that a test can tell
// which principal reached the handler.
var echoPrincipal = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	p := httpauth.MustPrincipal(r.Context())

	_, _ = w.Write([]byte(p.Username))
})

func TestBasicAuthAdmitsValidCredentials(t *testing.T) {
	t.Parallel()

	handler := httpauth.BasicAuth(newAuth(t))(echoPrincipal)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if body := rec.Body.String(); body != "alice" {
		t.Errorf("body = %q, want the authenticated username", body)
	}
}

func TestBasicAuthChallengesAMissingHeader(t *testing.T) {
	t.Parallel()

	handler := httpauth.BasicAuth(newAuth(t), httpauth.WithRealm("corp"))(echoPrincipal)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/private", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `realm="corp"`) {
		t.Errorf("WWW-Authenticate = %q, want the configured realm", challenge)
	}
}

func TestBasicAuthRejectsAWrongPassword(t *testing.T) {
	t.Parallel()

	handler := httpauth.BasicAuth(newAuth(t))(echoPrincipal)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "wrong")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want nothing: a rejection should not describe itself", rec.Body.String())
	}
}

func TestBasicAuthRejectsAnEmptyPasswordAsABadRequest(t *testing.T) {
	t.Parallel()

	handler := httpauth.BasicAuth(newAuth(t))(echoPrincipal)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestGroupRequirementIsForbiddenNotUnauthorised(t *testing.T) {
	t.Parallel()

	// The distinction matters to the client: 401 says try other
	// credentials, 403 says do not bother.
	auth := newAuth(t, ldapauth.WithMemberOfGroups())

	handler := httpauth.BasicAuth(auth, httpauth.RequireAnyGroup("ops"))(echoPrincipal)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequireAnyGroupAdmitsAMember(t *testing.T) {
	t.Parallel()

	auth := newAuth(t, ldapauth.WithMemberOfGroups())

	handler := httpauth.BasicAuth(auth, httpauth.RequireAnyGroup("ops", "devs"))(echoPrincipal)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRequireAllGroups(t *testing.T) {
	t.Parallel()

	auth := newAuth(t, ldapauth.WithMemberOfGroups())

	handler := httpauth.BasicAuth(auth, httpauth.RequireAllGroups("devs", "ops"))(echoPrincipal)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: alice is in devs but not ops", rec.Code)
	}
}

func TestDirectoryFailureIsServiceUnavailable(t *testing.T) {
	t.Parallel()

	dir := ldaptest.New(ldaptest.User(aliceDN, "alice-pw"))
	dir.SetDown("ldap://memory", true)

	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://memory"),
		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithoutRetry(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	defer func() { _ = auth.Close() }()

	handler := httpauth.BasicAuth(auth)(echoPrincipal)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: the directory being down is not the user's fault", rec.Code)
	}
}

func TestSkipLeavesARequestAlone(t *testing.T) {
	t.Parallel()

	handler := httpauth.BasicAuth(newAuth(t),
		httpauth.WithSkip(func(r *http.Request) bool { return r.URL.Path == "/healthz" }),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("status = %d body = %q, want the request to pass through", rec.Code, rec.Body.String())
	}
}

func TestCustomErrorHandler(t *testing.T) {
	t.Parallel()

	handler := httpauth.BasicAuth(newAuth(t),
		httpauth.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
			w.WriteHeader(http.StatusTeapot)

			if errors.Is(err, ldapauth.ErrInvalidCredentials) {
				_, _ = w.Write([]byte("nope"))
			}
		}),
	)(echoPrincipal)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "wrong")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot || rec.Body.String() != "nope" {
		t.Fatalf("status = %d body = %q, want the custom handler to have run", rec.Code, rec.Body.String())
	}
}

func TestLoginHandlerAcceptsJSON(t *testing.T) {
	t.Parallel()

	handler := httpauth.LoginHandler(newAuth(t),
		func(w http.ResponseWriter, _ *http.Request, p *ldapauth.Principal) {
			_, _ = w.Write([]byte(p.DN))
		},
	)

	body := strings.NewReader(`{"username":"alice","password":"alice-pw"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if rec.Body.String() != aliceDN {
		t.Errorf("body = %q, want %q", rec.Body.String(), aliceDN)
	}
}

func TestLoginHandlerAcceptsAForm(t *testing.T) {
	t.Parallel()

	handler := httpauth.LoginHandler(newAuth(t),
		func(w http.ResponseWriter, _ *http.Request, p *ldapauth.Principal) {
			_, _ = w.Write([]byte(p.Username))
		},
	)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=alice&password=alice-pw"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "alice" {
		t.Fatalf("status = %d body = %q, want a successful form login", rec.Code, rec.Body.String())
	}
}

func TestLoginHandlerRejectsAMalformedBody(t *testing.T) {
	t.Parallel()

	handler := httpauth.LoginHandler(newAuth(t),
		func(http.ResponseWriter, *http.Request, *ldapauth.Principal) {
			t.Error("the success handler ran for a malformed body")
		},
	)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestLoginHandlerBoundsTheBody(t *testing.T) {
	t.Parallel()

	handler := httpauth.LoginHandler(newAuth(t),
		func(http.ResponseWriter, *http.Request, *ldapauth.Principal) {
			t.Error("the success handler ran for an oversized body")
		},
		httpauth.WithMaxBodyBytes(32),
	)

	huge := `{"username":"alice","password":"` + strings.Repeat("a", 4096) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(huge))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("an oversized body was accepted")
	}
}

func TestMinimumDurationPadsTheResponse(t *testing.T) {
	t.Parallel()

	handler := httpauth.BasicAuth(newAuth(t), httpauth.WithMinimumDuration(40*time.Millisecond))(echoPrincipal)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "wrong")

	started := time.Now()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if elapsed := time.Since(started); elapsed < 40*time.Millisecond {
		t.Errorf("rejection took %s, want it padded to at least 40ms", elapsed)
	}
}

func TestRealmCannotBreakOutOfItsQuoting(t *testing.T) {
	t.Parallel()

	_, err := httpauth.NewPolicy(httpauth.WithRealm(`corp", nonce="x`))
	if err == nil {
		t.Fatal("a realm containing a quote was accepted")
	}
}

func TestStatusMapping(t *testing.T) {
	t.Parallel()

	cases := map[error]int{
		nil:                            http.StatusOK,
		ldapauth.ErrInvalidCredentials: http.StatusUnauthorized,
		httpauth.ErrNoCredentials:      http.StatusUnauthorized,
		httpauth.ErrForbidden:          http.StatusForbidden,
		ldapauth.ErrEmptyPassword:      http.StatusBadRequest,
		ldapauth.ErrInvalidUsername:    http.StatusBadRequest,
		ldapauth.ErrNoServerAvailable:  http.StatusServiceUnavailable,
		ldapauth.ErrClosed:             http.StatusServiceUnavailable,
	}

	for err, want := range cases {
		if got := httpauth.Status(err); got != want {
			t.Errorf("Status(%v) = %d, want %d", err, got, want)
		}
	}
}

func TestPrincipalIsAbsentWithoutTheMiddleware(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if _, ok := httpauth.PrincipalFrom(req.Context()); ok {
		t.Fatal("a principal appeared in a context that never went through the middleware")
	}
}
