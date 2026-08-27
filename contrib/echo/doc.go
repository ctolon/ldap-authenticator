// Package ldapauthecho is Echo middleware for github.com/ctolon/ldap-authenticator.
//
// It is a separate module so that the root package can promise a single
// dependency and mean it. The policy — realms, group requirements, status
// codes, response padding — lives in the httpauth package of the root
// module and is shared with the other framework adapters.
//
//	e := echo.New()
//	e.Use(ldapauthecho.BasicAuth(auth, httpauth.RequireAnyGroup("developers")))
//	e.GET("/me", func(c echo.Context) error {
//	    return c.JSON(200, ldapauthecho.MustIdentity(c))
//	})
package ldapauthecho
