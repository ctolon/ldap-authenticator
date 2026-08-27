package ldapauthgin

import (
	"github.com/gin-gonic/gin"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/httpauth"
)

// ContextKey is the key the identity is stored under in the Gin context,
// for handlers that would rather use c.Get than the request context.
const ContextKey = "ldapauth.identity"

// BasicAuth returns middleware that authenticates every request with HTTP
// Basic credentials, aborting with 401, 403, or 503 as appropriate and
// otherwise passing the principal to the handlers behind it.
//
// An option that does not validate panics: middleware is wired at startup,
// and there is nowhere to return an error to.
func BasicAuth(auth ldapauth.Authenticator, opts ...httpauth.Option) gin.HandlerFunc {
	policy, err := httpauth.NewPolicy(opts...)
	if err != nil {
		panic(err)
	}

	if auth == nil {
		panic("ldapauthgin: nil authenticator")
	}

	return func(c *gin.Context) {
		if policy.ShouldSkip(c.Request) {
			c.Next()

			return
		}

		username, password, ok := c.Request.BasicAuth()
		if !ok {
			reject(c, policy, httpauth.ErrNoCredentials)

			return
		}

		identity, err := policy.Authenticate(c.Request.Context(), auth, username, password)
		if err != nil {
			reject(c, policy, err)

			return
		}

		store(c, identity)

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
	auth ldapauth.Authenticator,
	onSuccess func(c *gin.Context, p ldapauth.Identity),
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
		username, password, err := httpauth.Credentials(c.Request, policy.MaxBodyBytes())
		if err != nil {
			reject(c, policy, err)

			return
		}

		identity, err := policy.Authenticate(c.Request.Context(), auth, username, password)
		if err != nil {
			reject(c, policy, err)

			return
		}

		store(c, identity)

		onSuccess(c, identity)
	}
}

// IdentityFrom returns the identity the middleware authenticated.
func IdentityFrom(c *gin.Context) (ldapauth.Identity, bool) {
	if value, ok := c.Get(ContextKey); ok {
		if identity, ok := value.(ldapauth.Identity); ok {
			return identity, true
		}
	}

	return httpauth.IdentityFrom(c.Request.Context())
}

// PrincipalFrom returns the identity as the concrete
// [ldapauth.Principal], for the common case where the mapper was not
// replaced and reading fields is nicer than calling accessors.
func PrincipalFrom(c *gin.Context) (*ldapauth.Principal, bool) {
	identity, ok := IdentityFrom(c)
	if !ok {
		return nil, false
	}

	return ldapauth.AsPrincipal(identity)
}

// MustIdentity returns the authenticated identity and panics if there is
// none, for handlers that are only ever mounted behind BasicAuth.
func MustIdentity(c *gin.Context) ldapauth.Identity {
	identity, ok := IdentityFrom(c)
	if !ok {
		panic("ldapauthgin: no identity in context; the handler is not behind BasicAuth")
	}

	return identity
}

// store puts the identity in both places a Gin handler might look: the
// Gin context, and the request context that everything else in the
// standard library reads.
func store(c *gin.Context, identity ldapauth.Identity) {
	c.Set(ContextKey, identity)
	c.Request = c.Request.WithContext(httpauth.WithIdentity(c.Request.Context(), identity))
}

func reject(c *gin.Context, policy *httpauth.Policy, err error) {
	policy.Reject(c.Writer, c.Request, err)
	c.Abort()
}
