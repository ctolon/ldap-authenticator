# Gin middleware for ldap-authenticator

LDAP authentication for [Gin](https://github.com/gin-gonic/gin), built on
[github.com/ctolon/ldap-authenticator](https://github.com/ctolon/ldap-authenticator).

```sh
go get github.com/ctolon/ldap-authenticator/contrib/gin
```

## Why this is a separate module

The root package promises exactly one direct dependency,
`github.com/go-ldap/ldap/v3`, and means it — a CI job fails the build if
that stops being true. Framework middleware cannot live there without
breaking that promise, so it lives here instead. Importing `ldapauth`
never puts Gin in your build graph; importing this module is how you ask
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

r := gin.New()

private := r.Group("/", ldapauthgin.BasicAuth(auth,
    httpauth.WithRealm("corp"),
    httpauth.RequireAnyGroup("developers", "ops"),
    httpauth.WithMinimumDuration(100*time.Millisecond),
))

private.GET("/me", func(c *gin.Context) {
    c.JSON(http.StatusOK, ldapauthgin.MustIdentity(c))
})
```

The middleware aborts the chain on failure, so a handler behind it only
ever runs for a request that authenticated.

## Login

```go
r.POST("/login", ldapauthgin.LoginHandler(auth,
    func(c *gin.Context, identity ldapauth.Identity) {
        // Start whatever a session is in your application. This library
        // deliberately does not decide that for you.
        session.Start(c, identity.GetDN(), identity.GetGroups())

        c.JSON(http.StatusOK, gin.H{"dn": identity.GetDN()})
    },
))
```

Credentials are read from a JSON body, a form body, or a Basic header —
whichever the request carries.

## Reading the identity

```go
identity, ok := ldapauthgin.IdentityFrom(c)     // the interface
principal, ok := ldapauthgin.PrincipalFrom(c)   // the concrete struct
identity := ldapauthgin.MustIdentity(c)         // panics if absent
```

The identity is put in both the Gin context, under `ldapauthgin.ContextKey`,
and the request context, so a plain `http.Handler` further down the chain
can read it with `httpauth.IdentityFrom(r.Context())`.

## What the caller sees

| | |
|---|---|
| 200 | authenticated, and in the required groups |
| 400 | the request was not a login: no username, an empty password |
| 401 | wrong or absent credentials, with a `WWW-Authenticate` challenge |
| 403 | the credentials were right and the groups were not |
| 503 | the directory could not answer |

The body is empty by default: a rejection that explains itself is a
rejection that helps somebody guess. `httpauth.WithErrorHandler` replaces
that if your API has a shape of its own.

## Options

Every option is an `httpauth.Option`, shared with the other adapters:
`WithRealm`, `RequireAnyGroup`, `RequireAllGroups`, `WithMinimumDuration`,
`WithErrorHandler`, `WithSkip`, `WithMaxBodyBytes`.

An option that does not validate panics, because middleware is wired at
startup and there is nowhere to return an error to. Use
`httpauth.NewPolicy` if you would rather handle it.

## Running the example

```sh
go run ./example
curl -u alice:s3cret localhost:8080/me
```

It runs against the in-memory directory in `ldaptest`, so there is no LDAP
server to install.

## More

- [Package documentation](https://pkg.go.dev/github.com/ctolon/ldap-authenticator/contrib/gin)
- [The library's documentation](https://github.com/ctolon/ldap-authenticator#readme)
- [HTTP integration guide](https://github.com/ctolon/ldap-authenticator/blob/main/docs/http.md)
