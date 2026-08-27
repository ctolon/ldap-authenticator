// Command example is a Gin server authenticating against the in-memory
// directory, so it runs with no LDAP server anywhere.
//
//	go run ./example
//	curl -u alice:s3cret localhost:8080/me
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	ldapauth "github.com/ctolon/ldap-authenticator"
	ldapauthgin "github.com/ctolon/ldap-authenticator/contrib/gin"
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

	r := gin.Default()

	r.POST("/login", ldapauthgin.LoginHandler(auth, func(c *gin.Context, identity ldapauth.Identity) {
		// A real application would start a session here. What a session
		// is remains its decision, not this library's.
		c.JSON(http.StatusOK, gin.H{"dn": identity.GetDN(), "groups": identity.GetGroups()})
	}))

	private := r.Group("/", ldapauthgin.BasicAuth(auth,
		httpauth.WithRealm("example"),
		httpauth.RequireAnyGroup("developers"),
	))

	private.GET("/me", func(c *gin.Context) {
		c.JSON(http.StatusOK, ldapauthgin.MustIdentity(c))
	})

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
