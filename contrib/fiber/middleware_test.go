package ldapauthfiber_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	ldapauth "github.com/ctolon/ldap-authenticator"
	ldapauthfiber "github.com/ctolon/ldap-authenticator/contrib/fiber"
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

func newApp(t *testing.T, auth *ldapauth.Client, opts ...httpauth.Option) *fiber.App {
	t.Helper()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(ldapauthfiber.BasicAuth(auth, opts...))
	app.Get("/private", func(c *fiber.Ctx) error {
		return c.SendString(ldapauthfiber.MustIdentity(c).GetUsername())
	})

	return app
}

func do(t *testing.T, app *fiber.App, req *http.Request) (int, string, http.Header) {
	t.Helper()

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	return resp.StatusCode, string(body), resp.Header
}

func TestBasicAuthAdmitsValidCredentials(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	status, body, _ := do(t, newApp(t, newAuth(t)), req)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	if body != "alice" {
		t.Errorf("body = %q, want the authenticated username", body)
	}
}

func TestBasicAuthChallengesAMissingHeader(t *testing.T) {
	t.Parallel()

	status, _, header := do(t, newApp(t, newAuth(t), httpauth.WithRealm("corp")),
		httptest.NewRequest(http.MethodGet, "/private", nil))

	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}

	if !strings.Contains(header.Get("WWW-Authenticate"), `realm="corp"`) {
		t.Errorf("WWW-Authenticate = %q, want the configured realm", header.Get("WWW-Authenticate"))
	}
}

func TestBasicAuthRejectsAWrongPassword(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "wrong")

	status, _, _ := do(t, newApp(t, newAuth(t)), req)

	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
}

func TestMalformedBasicHeaderIsUnauthorised(t *testing.T) {
	t.Parallel()

	// The adapter parses the header itself, because fasthttp has no
	// equivalent of net/http's BasicAuth.
	for _, header := range []string{"Basic", "Basic !!!notbase64", "Bearer abc", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon"))} {
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.Header.Set("Authorization", header)

		if status, _, _ := do(t, newApp(t, newAuth(t)), req); status != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", header, status)
		}
	}
}

func TestGroupRequirement(t *testing.T) {
	t.Parallel()

	auth := newAuth(t, ldapauth.WithMemberOfGroups())

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	if status, _, _ := do(t, newApp(t, auth, httpauth.RequireAnyGroup("devs")), req); status != http.StatusOK {
		t.Errorf("status = %d, want 200 for a member", status)
	}

	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	req.SetBasicAuth("alice", "alice-pw")

	if status, _, _ := do(t, newApp(t, auth, httpauth.RequireAnyGroup("ops")), req); status != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a non-member", status)
	}
}

func TestLoginHandler(t *testing.T) {
	t.Parallel()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Post("/login", ldapauthfiber.LoginHandler(newAuth(t),
		func(c *fiber.Ctx, identity ldapauth.Identity) error {
			return c.SendString(identity.GetDN())
		},
	))

	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(`{"username":"alice","password":"alice-pw"}`))
	req.Header.Set("Content-Type", "application/json")

	status, body, _ := do(t, app, req)

	if status != http.StatusOK || body != aliceDN {
		t.Fatalf("status = %d body = %q, want a successful login", status, body)
	}
}

func TestLoginHandlerAcceptsAForm(t *testing.T) {
	t.Parallel()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Post("/login", ldapauthfiber.LoginHandler(newAuth(t),
		func(c *fiber.Ctx, identity ldapauth.Identity) error {
			return c.SendString(identity.GetUsername())
		},
	))

	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader("username=alice&password=alice-pw"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	status, body, _ := do(t, app, req)

	if status != http.StatusOK || body != "alice" {
		t.Fatalf("status = %d body = %q, want a successful form login", status, body)
	}
}
