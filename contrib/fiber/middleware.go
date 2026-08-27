// Package ldapauthfiber is Fiber middleware for github.com/ctolon/ldap-authenticator.
//
// It is a separate module so that the root package can promise a single
// dependency and mean it. The policy — group requirements, status codes,
// response padding — lives in the httpauth package of the root module and
// is shared with the other framework adapters.
//
//	app := fiber.New()
//	app.Use(ldapauthfiber.BasicAuth(auth, httpauth.RequireAnyGroup("developers")))
//	app.Get("/me", func(c *fiber.Ctx) error {
//	    return c.JSON(ldapauthfiber.MustPrincipal(c))
//	})
//
// Fiber is built on fasthttp rather than net/http, so this adapter does not
// share the other three's request plumbing: it reads the Authorization
// header and the body itself, and writes the rejection through Fiber. The
// httpauth options that take an *http.Request — WithSkip and
// WithErrorHandler — therefore do nothing here. Skip with Fiber's own
// routing, and shape errors with a custom Fiber error handler.
package ldapauthfiber

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/httpauth"
)

// ContextKey is the Locals key the principal is stored under.
const ContextKey = "ldapauth.principal"

// BasicAuth returns middleware that authenticates every request with HTTP
// Basic credentials.
func BasicAuth(auth *ldapauth.Authenticator, opts ...httpauth.Option) fiber.Handler {
	policy, err := httpauth.NewPolicy(opts...)
	if err != nil {
		panic(err)
	}

	if auth == nil {
		panic("ldapauthfiber: nil authenticator")
	}

	return func(c *fiber.Ctx) error {
		username, password, ok := basicCredentials(c)
		if !ok {
			return reject(c, policy, httpauth.ErrNoCredentials)
		}

		principal, err := policy.Authenticate(c.UserContext(), auth, username, password)
		if err != nil {
			return reject(c, policy, err)
		}

		c.Locals(ContextKey, principal)

		return c.Next()
	}
}

// LoginHandler returns a handler that reads credentials from the request —
// JSON body, form body, or Basic header — and hands the authenticated
// principal to onSuccess.
func LoginHandler(
	auth *ldapauth.Authenticator,
	onSuccess func(c *fiber.Ctx, p *ldapauth.Principal) error,
	opts ...httpauth.Option,
) fiber.Handler {
	policy, err := httpauth.NewPolicy(opts...)
	if err != nil {
		panic(err)
	}

	if auth == nil {
		panic("ldapauthfiber: nil authenticator")
	}

	if onSuccess == nil {
		panic("ldapauthfiber: nil success handler")
	}

	return func(c *fiber.Ctx) error {
		username, password, err := credentials(c)
		if err != nil {
			return reject(c, policy, err)
		}

		principal, err := policy.Authenticate(c.UserContext(), auth, username, password)
		if err != nil {
			return reject(c, policy, err)
		}

		c.Locals(ContextKey, principal)

		return onSuccess(c, principal)
	}
}

// PrincipalFrom returns the principal the middleware authenticated.
func PrincipalFrom(c *fiber.Ctx) (*ldapauth.Principal, bool) {
	p, ok := c.Locals(ContextKey).(*ldapauth.Principal)

	return p, ok
}

// MustPrincipal returns the authenticated principal and panics if there is
// none, for handlers that are only ever mounted behind BasicAuth.
func MustPrincipal(c *fiber.Ctx) *ldapauth.Principal {
	p, ok := PrincipalFrom(c)
	if !ok {
		panic("ldapauthfiber: no principal in context; the handler is not behind BasicAuth")
	}

	return p
}

// credentials reads a username and password from wherever the request put
// them: the Authorization header, a JSON body, or a form body.
func credentials(c *fiber.Ctx) (username, password string, err error) {
	if user, pass, ok := basicCredentials(c); ok {
		return user, pass, nil
	}

	contentType, _, _ := strings.Cut(c.Get(fiber.HeaderContentType), ";")

	switch strings.TrimSpace(strings.ToLower(contentType)) {
	case fiber.MIMEApplicationJSON, "text/json":
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		// Fiber has already read the body into memory, bounded by the
		// app's BodyLimit; there is nothing left here to stream.
		if err := json.Unmarshal(c.Body(), &body); err != nil {
			return "", "", httpauth.ErrMalformedRequest
		}

		return body.Username, body.Password, nil

	case fiber.MIMEApplicationForm, fiber.MIMEMultipartForm:
		return c.FormValue("username"), c.FormValue("password"), nil

	default:
		return "", "", httpauth.ErrNoCredentials
	}
}

// basicCredentials parses an RFC 7617 Basic header. net/http has this, and
// fasthttp does not.
func basicCredentials(c *fiber.Ctx) (username, password string, ok bool) {
	header := c.Get(fiber.HeaderAuthorization)

	const prefix = "basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}

	user, pass, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", "", false
	}

	return user, pass, true
}

// reject writes the response for a failed authentication, using the same
// status mapping as every other adapter.
func reject(c *fiber.Ctx, policy *httpauth.Policy, err error) error {
	status := httpauth.Status(err)

	if status == http.StatusUnauthorized {
		c.Set(fiber.HeaderWWWAuthenticate, policy.Challenge())
	}

	return c.SendStatus(status)
}
