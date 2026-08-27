package httpauth_test

import (
	"bytes"
	"errors"
	"mime/multipart"
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

func newAuth(t *testing.T, opts ...ldapauth.Option) *ldapauth.Client {
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

// echoIdentity writes the authenticated username, so that a test can tell
// which identity reached the handler.
var echoIdentity = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(httpauth.MustIdentity(r.Context()).GetUsername()))
})

func TestBasicAuthAdmitsValidCredentials(t *testing.T) {
	t.Parallel()

	handler := httpauth.BasicAuth(newAuth(t))(echoIdentity)

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

	handler := httpauth.BasicAuth(newAuth(t), httpauth.WithRealm("corp"))(echoIdentity)

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

	handler := httpauth.BasicAuth(newAuth(t))(echoIdentity)

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

	handler := httpauth.BasicAuth(newAuth(t))(echoIdentity)

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

	handler := httpauth.BasicAuth(auth, httpauth.RequireAnyGroup("ops"))(echoIdentity)

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

	handler := httpauth.BasicAuth(auth, httpauth.RequireAnyGroup("ops", "devs"))(echoIdentity)

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

	handler := httpauth.BasicAuth(auth, httpauth.RequireAllGroups("devs", "ops"))(echoIdentity)

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

	handler := httpauth.BasicAuth(auth)(echoIdentity)

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
	)(echoIdentity)

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
		func(w http.ResponseWriter, _ *http.Request, identity ldapauth.Identity) {
			_, _ = w.Write([]byte(identity.GetDN()))
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
		func(w http.ResponseWriter, _ *http.Request, identity ldapauth.Identity) {
			_, _ = w.Write([]byte(identity.GetUsername()))
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
		func(http.ResponseWriter, *http.Request, ldapauth.Identity) {
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
		func(http.ResponseWriter, *http.Request, ldapauth.Identity) {
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

	handler := httpauth.BasicAuth(newAuth(t), httpauth.WithMinimumDuration(40*time.Millisecond))(echoIdentity)

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

	if _, ok := httpauth.IdentityFrom(req.Context()); ok {
		t.Fatal("a principal appeared in a context that never went through the middleware")
	}
}

func TestLoginHandlerAcceptsMultipart(t *testing.T) {
	t.Parallel()

	// ParseForm does not parse a multipart body, so the multipart support
	// this package documented used to return empty fields for every
	// request.
	var body bytes.Buffer

	writer := multipart.NewWriter(&body)

	for field, value := range map[string]string{"username": "alice", "password": "alice-pw"} {
		if err := writer.WriteField(field, value); err != nil {
			t.Fatalf("writing %s: %v", field, err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("closing the multipart writer: %v", err)
	}

	handler := httpauth.LoginHandler(newAuth(t),
		func(w http.ResponseWriter, _ *http.Request, identity ldapauth.Identity) {
			_, _ = w.Write([]byte(identity.GetUsername()))
		},
	)

	req := httptest.NewRequest(http.MethodPost, "/login", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "alice" {
		t.Fatalf("status = %d body = %q, want a successful multipart login", rec.Code, rec.Body.String())
	}
}

func TestJSONTrailingContentIsRejected(t *testing.T) {
	t.Parallel()

	// Decode stops at the end of the first value, so a body with a second
	// object behind the credentials used to be accepted.
	handler := httpauth.LoginHandler(newAuth(t),
		func(http.ResponseWriter, *http.Request, ldapauth.Identity) {
			t.Error("the success handler ran for a body with trailing content")
		},
	)

	body := `{"username":"alice","password":"alice-pw"}{"username":"root"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAnOversizedJSONBodyIsRejectedRatherThanTruncated(t *testing.T) {
	t.Parallel()

	// A LimitReader truncates, so a valid object inside the limit used to
	// be accepted with anything at all behind it. A MaxBytesReader errors.
	handler := httpauth.LoginHandler(newAuth(t),
		func(http.ResponseWriter, *http.Request, ldapauth.Identity) {
			t.Error("the success handler ran for an oversized body")
		},
		httpauth.WithMaxBodyBytes(64),
	)

	body := `{"username":"alice","password":"alice-pw"}` + strings.Repeat(" ", 4096)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("an oversized body was truncated and accepted")
	}
}

func TestPolicyAccessorsReportWhatTheAdaptersNeed(t *testing.T) {
	t.Parallel()

	policy, err := httpauth.NewPolicy(
		httpauth.WithMaxBodyBytes(1234),
		httpauth.WithSkip(func(r *http.Request) bool { return r.URL.Path == "/healthz" }),
	)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	if got := policy.MaxBodyBytes(); got != 1234 {
		t.Errorf("MaxBodyBytes = %d, want 1234", got)
	}

	if !policy.ShouldSkip(httptest.NewRequest(http.MethodGet, "/healthz", nil)) {
		t.Error("ShouldSkip = false for a path the predicate skips")
	}

	if policy.ShouldSkip(httptest.NewRequest(http.MethodGet, "/private", nil)) {
		t.Error("ShouldSkip = true for a path the predicate does not skip")
	}

	// An adapter with no *http.Request — Fiber — must get a usable answer
	// rather than a panic.
	if policy.ShouldSkip(nil) {
		t.Error("ShouldSkip(nil) = true")
	}
}

func TestLockoutIsTooManyRequests(t *testing.T) {
	t.Parallel()

	// The credentials were never tried, so 401 would be a lie and 503
	// would be somebody else's problem. 429 is both true and actionable.
	if got := httpauth.Status(ldapauth.ErrTooManyAttempts); got != http.StatusTooManyRequests {
		t.Errorf("Status = %d, want 429", got)
	}

	auth := newAuth(t, ldapauth.WithLockoutProtection(2, time.Minute, time.Minute), ldapauth.WithoutRetry())

	handler := httpauth.BasicAuth(auth)(echoIdentity)

	send := func(password string) int {
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.SetBasicAuth("alice", password)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		return rec.Code
	}

	for range 2 {
		if code := send("wrong"); code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", code)
		}
	}

	if code := send("wrong"); code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 once the account is in its cooldown", code)
	}
}
