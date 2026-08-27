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
//	    return c.JSON(200, ldapauthecho.MustPrincipal(c))
//	})
package ldapauthecho

import (
	"github.com/labstack/echo/v4"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/httpauth"
)

// ContextKey is the key the principal is stored under in the Echo context,
// for handlers that would rather use c.Get than the request context.
const ContextKey = "ldapauth.principal"

// BasicAuth returns middleware that authenticates every request with HTTP
// Basic credentials.
//
// It writes the rejection itself and returns nil rather than returning an
// echo.HTTPError, so that Echo's error handler cannot turn a bare 401 into
// a response body describing why the login failed.
func BasicAuth(auth *ldapauth.Authenticator, opts ...httpauth.Option) echo.MiddlewareFunc {
	policy, err := httpauth.NewPolicy(opts...)
	if err != nil {
		panic(err)
	}

	if auth == nil {
		panic("ldapauthecho: nil authenticator")
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			request := c.Request()

			username, password, ok := request.BasicAuth()
			if !ok {
				policy.Reject(c.Response(), request, httpauth.ErrNoCredentials)

				return nil
			}

			principal, err := policy.Authenticate(request.Context(), auth, username, password)
			if err != nil {
				policy.Reject(c.Response(), request, err)

				return nil
			}

			store(c, principal)

			return next(c)
		}
	}
}

// LoginHandler returns a handler that reads credentials from the request —
// JSON body, form body, or Basic header — and hands the authenticated
// principal to onSuccess.
func LoginHandler(
	auth *ldapauth.Authenticator,
	onSuccess func(c echo.Context, p *ldapauth.Principal) error,
	opts ...httpauth.Option,
) echo.HandlerFunc {
	policy, err := httpauth.NewPolicy(opts...)
	if err != nil {
		panic(err)
	}

	if auth == nil {
		panic("ldapauthecho: nil authenticator")
	}

	if onSuccess == nil {
		panic("ldapauthecho: nil success handler")
	}

	return func(c echo.Context) error {
		request := c.Request()

		username, password, err := httpauth.Credentials(request, httpauth.DefaultMaxBodyBytes)
		if err != nil {
			policy.Reject(c.Response(), request, err)

			return nil
		}

		principal, err := policy.Authenticate(request.Context(), auth, username, password)
		if err != nil {
			policy.Reject(c.Response(), request, err)

			return nil
		}

		store(c, principal)

		return onSuccess(c, principal)
	}
}

// PrincipalFrom returns the principal the middleware authenticated.
func PrincipalFrom(c echo.Context) (*ldapauth.Principal, bool) {
	if p, ok := c.Get(ContextKey).(*ldapauth.Principal); ok {
		return p, true
	}

	return httpauth.PrincipalFrom(c.Request().Context())
}

// MustPrincipal returns the authenticated principal and panics if there is
// none, for handlers that are only ever mounted behind BasicAuth.
func MustPrincipal(c echo.Context) *ldapauth.Principal {
	p, ok := PrincipalFrom(c)
	if !ok {
		panic("ldapauthecho: no principal in context; the handler is not behind BasicAuth")
	}

	return p
}

func store(c echo.Context, p *ldapauth.Principal) {
	c.Set(ContextKey, p)
	c.SetRequest(c.Request().WithContext(httpauth.WithPrincipal(c.Request().Context(), p)))
}
