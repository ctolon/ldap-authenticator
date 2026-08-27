// Package ldapauthgin is Gin middleware for github.com/ctolon/ldap-authenticator.
//
// It is a separate module so that the root package can promise a single
// dependency and mean it: importing ldapauth never puts Gin in your build
// graph. The policy — realms, group requirements, status codes, response
// padding — lives in the httpauth package of the root module and is shared
// with the other framework adapters, so behaviour cannot drift between
// them.
//
//	r := gin.New()
//	r.Use(ldapauthgin.BasicAuth(auth, httpauth.RequireAnyGroup("developers")))
//	r.GET("/me", func(c *gin.Context) {
//	    c.JSON(200, ldapauthgin.MustIdentity(c))
//	})
package ldapauthgin
