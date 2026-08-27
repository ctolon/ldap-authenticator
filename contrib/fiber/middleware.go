package ldapauthfiber

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/httpauth"
)

// ContextKey is the Locals key the identity is stored under.
const ContextKey = "ldapauth.identity"

// BasicAuth returns middleware that authenticates every request with HTTP
// Basic credentials.
func BasicAuth(auth ldapauth.Authenticator, opts ...httpauth.Option) fiber.Handler {
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

		identity, err := policy.Authenticate(c.UserContext(), auth, username, password)
		if err != nil {
			return reject(c, policy, err)
		}

		c.Locals(ContextKey, identity)

		return c.Next()
	}
}

// LoginHandler returns a handler that reads credentials from the request —
// JSON body, form body, or Basic header — and hands the authenticated
// principal to onSuccess.
func LoginHandler(
	auth ldapauth.Authenticator,
	onSuccess func(c *fiber.Ctx, p ldapauth.Identity) error,
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

		identity, err := policy.Authenticate(c.UserContext(), auth, username, password)
		if err != nil {
			return reject(c, policy, err)
		}

		c.Locals(ContextKey, identity)

		return onSuccess(c, identity)
	}
}

// IdentityFrom returns the identity the middleware authenticated.
func IdentityFrom(c *fiber.Ctx) (ldapauth.Identity, bool) {
	identity, ok := c.Locals(ContextKey).(ldapauth.Identity)

	return identity, ok
}

// PrincipalFrom returns the identity as the concrete
// [ldapauth.Principal], for the common case where the mapper was not
// replaced and reading fields is nicer than calling accessors.
func PrincipalFrom(c *fiber.Ctx) (*ldapauth.Principal, bool) {
	identity, ok := IdentityFrom(c)
	if !ok {
		return nil, false
	}

	return ldapauth.AsPrincipal(identity)
}

// MustIdentity returns the authenticated identity and panics if there is
// none, for handlers that are only ever mounted behind BasicAuth.
func MustIdentity(c *fiber.Ctx) ldapauth.Identity {
	identity, ok := IdentityFrom(c)
	if !ok {
		panic("ldapauthfiber: no identity in context; the handler is not behind BasicAuth")
	}

	return identity
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

// basicCredentials parses an RFC 7617 Basic header.
//
// fasthttp has no equivalent of net/http's BasicAuth, so the header is
// handed to net/http's parser through a bare Request rather than being
// parsed again here. RFC 7617 has more corners than it looks — a password
// may legitimately contain a colon, the payload need not be UTF-8, and
// getting the base64 padding wrong turns a rejection into a panic — and
// none of them are worth meeting twice.
func basicCredentials(c *fiber.Ctx) (username, password string, ok bool) {
	header := c.Get(fiber.HeaderAuthorization)
	if header == "" {
		return "", "", false
	}

	probe := &http.Request{Header: http.Header{"Authorization": []string{header}}}

	return probe.BasicAuth()
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
