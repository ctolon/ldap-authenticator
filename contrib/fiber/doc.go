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
//	    return c.JSON(ldapauthfiber.MustIdentity(c))
//	})
//
// Fiber is built on fasthttp, which also means this module does not build
// for the wasm targets that the rest of this repository does — fasthttp's
// listener has no implementation for them.
//
// Fiber is built on fasthttp rather than net/http, so this adapter does not
// share the other three's request plumbing: it reads the Authorization
// header and the body itself, and writes the rejection through Fiber. The
// httpauth options that take an *http.Request — WithSkip and
// WithErrorHandler — therefore do nothing here. Skip with Fiber's own
// routing, and shape errors with a custom Fiber error handler.
package ldapauthfiber
