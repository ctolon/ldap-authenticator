# Fiber middleware for ldap-authenticator

LDAP authentication for [Fiber](https://github.com/gofiber/fiber), built on
[github.com/ctolon/ldap-authenticator](https://github.com/ctolon/ldap-authenticator).

```sh
go get github.com/ctolon/ldap-authenticator/contrib/fiber
```

## Why this is a separate module

The root package promises exactly one direct dependency,
`github.com/go-ldap/ldap/v3`, and means it — a CI job fails the build if
that stops being true. Framework middleware cannot live there without
breaking that promise, so it lives here instead. Importing `ldapauth`
never puts Fiber in your build graph; importing this module is how you ask
for it.

The policy — realms, group requirements, status codes, response padding —
lives in the root module's `httpauth` package and is shared with the
net/http, Gin, Echo, and Fiber adapters alike. There is one implementation
of "what a 403 means here", not four.

## Basic auth

```go
auth, err := ldapauth.New(
    ldapauth.WithURL("ldaps://dc1.corp.example:636"),
    ldapauth.WithDirectBind("uid={{username}},ou=people,dc=corp,dc=example"),
    ldapauth.WithMemberOfGroups(),
)
if err != nil {
    log.Fatal(err)
}
defer auth.Close()

app := fiber.New()

app.Use(ldapauthfiber.BasicAuth(auth,
    httpauth.WithRealm("corp"),
    httpauth.RequireAnyGroup("developers", "ops"),
    httpauth.WithMinimumDuration(100*time.Millisecond),
))

app.Get("/me", func(c *fiber.Ctx) error {
    return c.JSON(ldapauthfiber.MustIdentity(c))
})
```

## Login

```go
app.Post("/login", ldapauthfiber.LoginHandler(auth,
    func(c *fiber.Ctx, identity ldapauth.Identity) error {
        // Start whatever a session is in your application. This library
        // deliberately does not decide that for you.
        return c.JSON(fiber.Map{"dn": identity.GetDN()})
    },
))
```

Credentials are read from a JSON body, a form body, or a Basic header —
whichever the request carries.

## Reading the identity

```go
identity, ok := ldapauthfiber.IdentityFrom(c)     // the interface
principal, ok := ldapauthfiber.PrincipalFrom(c)   // the concrete struct
identity := ldapauthfiber.MustIdentity(c)         // panics if absent
```

The identity lives in `c.Locals`, under `ldapauthfiber.ContextKey`.

## What is different here

Fiber is built on fasthttp rather than net/http, and that has three
consequences worth knowing:

- **`httpauth.WithSkip` and `httpauth.WithErrorHandler` do nothing**, because
  both take an `*http.Request` and there is not one. Skip with Fiber's own
  routing, and shape errors with a Fiber error handler.
- **The context for the authentication is `c.UserContext()`.** Set it if you
  want a deadline or a trace to reach the directory.
- **This module does not build for the wasm targets** that the rest of the
  repository does. fasthttp's listener has no implementation for them.

The Authorization header is still parsed by net/http's own parser rather
than by hand: RFC 7617 has more corners than it looks, and none of them are
worth meeting twice.

## What the caller sees

| | |
|---|---|
| 200 | authenticated, and in the required groups |
| 400 | the request was not a login: no username, an empty password |
| 401 | wrong or absent credentials, with a `WWW-Authenticate` challenge |
| 403 | the credentials were right and the groups were not |
| 503 | the directory could not answer |

## Running the example

```sh
go run ./example
curl -u alice:s3cret localhost:8080/me
```

It runs against the in-memory directory in `ldaptest`, so there is no LDAP
server to install.

## More

- [Package documentation](https://pkg.go.dev/github.com/ctolon/ldap-authenticator/contrib/fiber)
- [The library's documentation](https://github.com/ctolon/ldap-authenticator#readme)
- [HTTP integration guide](https://github.com/ctolon/ldap-authenticator/blob/main/docs/http.md)
