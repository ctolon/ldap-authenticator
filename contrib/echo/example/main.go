// Command example is an Echo server authenticating against the in-memory
// directory, so it runs with no LDAP server anywhere.
//
//	go run ./example
//	curl -u alice:s3cret localhost:8080/me
package main

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"

	ldapauth "github.com/ctolon/ldap-authenticator"
	ldapauthecho "github.com/ctolon/ldap-authenticator/contrib/echo"
	"github.com/ctolon/ldap-authenticator/httpauth"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

func main() {
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
		log.Fatal(err)
	}

	defer func() { _ = auth.Close() }()

	e := echo.New()

	e.POST("/login", ldapauthecho.LoginHandler(auth, func(c echo.Context, p *ldapauth.Principal) error {
		return c.JSON(http.StatusOK, map[string]any{"dn": p.DN, "groups": p.Groups})
	}))

	private := e.Group("", ldapauthecho.BasicAuth(auth,
		httpauth.WithRealm("example"),
		httpauth.RequireAnyGroup("developers"),
	))

	private.GET("/me", func(c echo.Context) error {
		return c.JSON(http.StatusOK, ldapauthecho.MustPrincipal(c))
	})

	e.Logger.Fatal(e.Start(":8080"))
}
