package ldapauthgin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	ldapauth "github.com/ctolon/ldap-authenticator"
	ldapauthgin "github.com/ctolon/ldap-authenticator/contrib/gin"
	"github.com/ctolon/ldap-authenticator/httpauth"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const (
	peopleDN = "ou=people,dc=example,dc=com"
	aliceDN  = "uid=alice," + peopleDN
	devsDN   = "cn=devs,ou=groups,dc=example,dc=com"
)

func newAuth(t *testing.T, opts ...ldapauth.Option) *ldapauth.Client {
	t.Helper()

	dir := ldaptest.New(
		ldaptest.User(aliceDN, "alice-pw").
			With("uid", "alice").
			With("objectClass", "inetOrgPerson").
			With("memberOf", devsDN),
		ldaptest.Group(devsDN).With("cn", "devs"),
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

func newEngine(t *testing.T, auth *ldapauth.Client, opts ...httpauth.Option) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(ldapauthgin.BasicAuth(auth, opts...))
	r.GET("/private", func(c *gin.Context) {
		c.String(http.StatusOK, ldapauthgin.MustIdentity(c).GetUsername())
	})

	return r
}

func do(t *testing.T, h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

func TestBasicAuthAdmitsValidCredentials(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	rec := do(t, newEngine(t, newAuth(t)), req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if rec.Body.String() != "alice" {
		t.Errorf("body = %q, want the authenticated username", rec.Body.String())
	}
}

func TestBasicAuthChallengesAMissingHeader(t *testing.T) {
	t.Parallel()

	rec := do(t, newEngine(t, newAuth(t), httpauth.WithRealm("corp")),
		httptest.NewRequest(http.MethodGet, "/private", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `realm="corp"`) {
		t.Errorf("WWW-Authenticate = %q, want the configured realm", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestBasicAuthAbortsTheChain(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	reached := false

	r := gin.New()
	r.Use(ldapauthgin.BasicAuth(newAuth(t)))
	r.GET("/private", func(c *gin.Context) {
		reached = true

		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "wrong")

	if rec := do(t, r, req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	if reached {
		t.Fatal("the handler ran behind a failed authentication")
	}
}

func TestGroupRequirement(t *testing.T) {
	t.Parallel()

	auth := newAuth(t, ldapauth.WithMemberOfGroups())

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	if rec := do(t, newEngine(t, auth, httpauth.RequireAnyGroup("devs")), req); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for a member", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	if rec := do(t, newEngine(t, auth, httpauth.RequireAnyGroup("ops")), req); rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a non-member", rec.Code)
	}
}

func TestLoginHandler(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.POST("/login", ldapauthgin.LoginHandler(newAuth(t),
		func(c *gin.Context, identity ldapauth.Identity) {
			c.String(http.StatusOK, identity.GetDN())
		},
	))

	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(`{"username":"alice","password":"alice-pw"}`))
	req.Header.Set("Content-Type", "application/json")

	rec := do(t, r, req)

	if rec.Code != http.StatusOK || rec.Body.String() != aliceDN {
		t.Fatalf("status = %d body = %q, want a successful login", rec.Code, rec.Body.String())
	}
}

func TestPrincipalReachesBothContexts(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(ldapauthgin.BasicAuth(newAuth(t)))
	r.GET("/private", func(c *gin.Context) {
		if _, ok := ldapauthgin.IdentityFrom(c); !ok {
			t.Error("the principal is missing from the Gin context")
		}

		if _, ok := httpauth.IdentityFrom(c.Request.Context()); !ok {
			t.Error("the principal is missing from the request context")
		}

		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	if rec := do(t, r, req); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
