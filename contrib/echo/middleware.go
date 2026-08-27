package ldapauthecho

import (
	"github.com/labstack/echo/v4"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/httpauth"
)

// ContextKey is the key the identity is stored under in the Echo context,
// for handlers that would rather use c.Get than the request context.
const ContextKey = "ldapauth.identity"

// BasicAuth returns middleware that authenticates every request with HTTP
// Basic credentials.
//
// It writes the rejection itself and returns nil rather than returning an
// echo.HTTPError, so that Echo's error handler cannot turn a bare 401 into
// a response body describing why the login failed.
func BasicAuth(auth ldapauth.Authenticator, opts ...httpauth.Option) echo.MiddlewareFunc {
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

			if policy.ShouldSkip(request) {
				return next(c)
			}

			username, password, ok := request.BasicAuth()
			if !ok {
				policy.Reject(c.Response(), request, httpauth.ErrNoCredentials)

				return nil
			}

			identity, err := policy.Authenticate(request.Context(), auth, username, password)
			if err != nil {
				policy.Reject(c.Response(), request, err)

				return nil
			}

			store(c, identity)

			return next(c)
		}
	}
}

// LoginHandler returns a handler that reads credentials from the request —
// JSON body, form body, or Basic header — and hands the authenticated
// principal to onSuccess.
func LoginHandler(
	auth ldapauth.Authenticator,
	onSuccess func(c echo.Context, p ldapauth.Identity) error,
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

		username, password, err := httpauth.Credentials(request, policy.MaxBodyBytes())
		if err != nil {
			policy.Reject(c.Response(), request, err)

			return nil
		}

		identity, err := policy.Authenticate(request.Context(), auth, username, password)
		if err != nil {
			policy.Reject(c.Response(), request, err)

			return nil
		}

		store(c, identity)

		return onSuccess(c, identity)
	}
}

// IdentityFrom returns the identity the middleware authenticated.
func IdentityFrom(c echo.Context) (ldapauth.Identity, bool) {
	if identity, ok := c.Get(ContextKey).(ldapauth.Identity); ok {
		return identity, true
	}

	return httpauth.IdentityFrom(c.Request().Context())
}

// PrincipalFrom returns the identity as the concrete
// [ldapauth.Principal], for the common case where the mapper was not
// replaced and reading fields is nicer than calling accessors.
func PrincipalFrom(c echo.Context) (*ldapauth.Principal, bool) {
	identity, ok := IdentityFrom(c)
	if !ok {
		return nil, false
	}

	return ldapauth.AsPrincipal(identity)
}

// MustIdentity returns the authenticated identity and panics if there is
// none, for handlers that are only ever mounted behind BasicAuth.
func MustIdentity(c echo.Context) ldapauth.Identity {
	identity, ok := IdentityFrom(c)
	if !ok {
		panic("ldapauthecho: no identity in context; the handler is not behind BasicAuth")
	}

	return identity
}

func store(c echo.Context, identity ldapauth.Identity) {
	c.Set(ContextKey, identity)
	c.SetRequest(c.Request().WithContext(httpauth.WithIdentity(c.Request().Context(), identity)))
}
