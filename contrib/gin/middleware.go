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
//	    c.JSON(200, ldapauthgin.MustPrincipal(c))
//	})
package ldapauthgin

import (
	"github.com/gin-gonic/gin"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/httpauth"
)

// ContextKey is the key the principal is stored under in the Gin context,
// for handlers that would rather use c.Get than the request context.
const ContextKey = "ldapauth.principal"

// BasicAuth returns middleware that authenticates every request with HTTP
// Basic credentials, aborting with 401, 403, or 503 as appropriate and
// otherwise passing the principal to the handlers behind it.
//
// An option that does not validate panics: middleware is wired at startup,
// and there is nowhere to return an error to.
func BasicAuth(auth *ldapauth.Authenticator, opts ...httpauth.Option) gin.HandlerFunc {
	policy, err := httpauth.NewPolicy(opts...)
	if err != nil {
		panic(err)
	}

	if auth == nil {
		panic("ldapauthgin: nil authenticator")
	}

	return func(c *gin.Context) {
		username, password, ok := c.Request.BasicAuth()
		if !ok {
			reject(c, policy, httpauth.ErrNoCredentials)

			return
		}

		principal, err := policy.Authenticate(c.Request.Context(), auth, username, password)
		if err != nil {
			reject(c, policy, err)

			return
		}

		store(c, principal)

		c.Next()
	}
}

// LoginHandler returns a handler that reads credentials from the request —
// JSON body, form body, or Basic header — and hands the authenticated
// principal to onSuccess.
//
// It issues no session and no token. What a successful login becomes is
// the application's decision; see the httpauth package for why.
func LoginHandler(
	auth *ldapauth.Authenticator,
	onSuccess func(c *gin.Context, p *ldapauth.Principal),
	opts ...httpauth.Option,
) gin.HandlerFunc {
	policy, err := httpauth.NewPolicy(opts...)
	if err != nil {
		panic(err)
	}

	if auth == nil {
		panic("ldapauthgin: nil authenticator")
	}

	if onSuccess == nil {
		panic("ldapauthgin: nil success handler")
	}

	return func(c *gin.Context) {
		username, password, err := httpauth.Credentials(c.Request, httpauth.DefaultMaxBodyBytes)
		if err != nil {
			reject(c, policy, err)

			return
		}

		principal, err := policy.Authenticate(c.Request.Context(), auth, username, password)
		if err != nil {
			reject(c, policy, err)

			return
		}

		store(c, principal)

		onSuccess(c, principal)
	}
}

// PrincipalFrom returns the principal the middleware authenticated.
func PrincipalFrom(c *gin.Context) (*ldapauth.Principal, bool) {
	if value, ok := c.Get(ContextKey); ok {
		if p, ok := value.(*ldapauth.Principal); ok {
			return p, true
		}
	}

	return httpauth.PrincipalFrom(c.Request.Context())
}

// MustPrincipal returns the authenticated principal and panics if there is
// none, for handlers that are only ever mounted behind BasicAuth.
func MustPrincipal(c *gin.Context) *ldapauth.Principal {
	p, ok := PrincipalFrom(c)
	if !ok {
		panic("ldapauthgin: no principal in context; the handler is not behind BasicAuth")
	}

	return p
}

// store puts the principal in both places a Gin handler might look: the
// Gin context, and the request context that everything else in the
// standard library reads.
func store(c *gin.Context, p *ldapauth.Principal) {
	c.Set(ContextKey, p)
	c.Request = c.Request.WithContext(httpauth.WithPrincipal(c.Request.Context(), p))
}

func reject(c *gin.Context, policy *httpauth.Policy, err error) {
	policy.Reject(c.Writer, c.Request, err)
	c.Abort()
}
