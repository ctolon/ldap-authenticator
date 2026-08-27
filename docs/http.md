# HTTP

Four adapters, one policy. `httpauth` is in the root module because it
needs nothing but the standard library; Gin, Echo, and Fiber are separate
modules because they do.

| | import | needs |
|---|---|---|
| net/http, chi, gorilla/mux | `ldap-authenticator/httpauth` | nothing extra |
| Gin | `ldap-authenticator/contrib/gin` | `gin-gonic/gin` |
| Echo | `ldap-authenticator/contrib/echo` | `labstack/echo/v4` |
| Fiber | `ldap-authenticator/contrib/fiber` | `gofiber/fiber/v2` |

All four share the same `httpauth.Policy`: the same realm handling, the
same group requirements, the same status codes, the same response padding.
There is one implementation of "what a 403 means here", not four.

## Basic auth

```go
mux := http.NewServeMux()

mux.Handle("GET /private", httpauth.BasicAuth(auth,
    httpauth.WithRealm("corp"),
    httpauth.RequireAnyGroup("developers", "ops"),
    httpauth.WithMinimumDuration(100*time.Millisecond),
)(privateHandler))
```

The signature is `func(http.Handler) http.Handler`, which is what chi,
gorilla/mux, and every other net/http router expects. There is nothing
framework-specific about it:

```go
r := chi.NewRouter()

r.Group(func(r chi.Router) {
    r.Use(httpauth.BasicAuth(auth, httpauth.RequireAnyGroup("developers")))
    r.Get("/private", privateHandler)
})
```

## Login

```go
mux.Handle("POST /login", httpauth.LoginHandler(auth,
    func(w http.ResponseWriter, r *http.Request, identity ldapauth.Identity) {
        session.Start(w, identity.GetDN(), identity.GetGroups())
    },
))
```

Credentials are read from a JSON body, a form body, or a Basic header —
whichever the request carries:

```json
{"username": "alice", "password": "..."}
```

```
username=alice&password=...
```

The body is bounded by `httpauth.WithMaxBodyBytes`, 64 KiB by default.
Credentials are small; a body larger than that is not a login, and a body
over the limit is **rejected** rather than truncated — reading the first 64
KiB and accepting whatever valid JSON was in it would mean the limit
bounded memory and nothing else.

A JSON body must also be *only* the credentials. `{"username":"a",
"password":"b"}{"username":"root"}` is a 400, because a decoder stops at
the end of the first value and would otherwise never see the second.

All three adapters apply the same limit. So does the Fiber one, which
cannot see an `*http.Request` — set `fiber.Config.BodyLimit` as well
there, because by the time the adapter can check the length Fiber has
already read the body into memory.

### Why there is no session here

`LoginHandler` hands you the identity and stops. It mints no cookie, no
JWT, no server-side session.

That is not an omission. How long a session lives, where it is stored, what
else it carries, how it is revoked, and what happens when the directory
says the user is gone are all decisions your application has already made
or is about to — and a library that made them for you would be a library
you had to work around. Every session library in Go takes a user identifier
and some claims; that is what you have been handed.

## Reading the identity

```go
identity := httpauth.MustIdentity(r.Context())      // panics if absent
identity, ok := httpauth.IdentityFrom(r.Context())  // does not
principal, ok := httpauth.PrincipalFrom(r.Context())// the concrete struct
```

`MustIdentity` is for a handler that is only ever mounted behind the
middleware, where a missing identity is a routing mistake rather than a
runtime condition. `IdentityFrom` is for a handler that is sometimes
mounted behind it.

For a test, put one in directly and skip the directory entirely:

```go
ctx := httpauth.WithIdentity(r.Context(), &ldapauth.Principal{
    Username: "alice",
    Groups:   []string{"developers"},
})
```

## Status codes

| | when | body |
|---|---|---|
| 400 | the request was not a login: no username, an empty password, a malformed body | empty |
| 401 | wrong or absent credentials | empty, with `WWW-Authenticate` |
| 403 | the credentials were right and the groups were not | empty |
| 429 | this account is in a local cooldown, under `WithLockoutProtection` | empty |
| 503 | the directory could not answer | empty |

The distinction between 401 and 403 is the one that matters to a client:
401 says try other credentials, 403 says do not bother.

`httpauth.Status(err)` is that mapping, exported, so an adapter for another
framework or a handler with its own error shape does not have to
reconstruct it from the sentinels.

The bodies are empty on purpose. A rejection that explains itself is a
rejection that helps somebody guess, and the error text can name the
account and, on some directories, the reason it was refused. Replace it
when your API has a shape of its own:

```go
httpauth.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(httpauth.Status(err))

    _ = json.NewEncoder(w).Encode(problem{
        Type:  "https://example.com/probs/unauthorized",
        Title: http.StatusText(httpauth.Status(err)),
    })
})
```

Write a response, and do not write the error.

## Group requirements

```go
httpauth.RequireAnyGroup("developers", "ops")   // at least one
httpauth.RequireAllGroups("employees", "mfa")   // every one
```

Both may be given; both must then pass.

`RequireAnyGroup()` with no names is false and `RequireAllGroups()` with no
names is true. Both readings are the vacuous ones, and both are the safe
ones: "in any of nothing" should not admit anybody, and "no group is
required" should not reject anybody.

A group requirement with no group source configured on the authenticator
rejects everybody, because the identity arrives with no groups. Configure
`WithMemberOfGroups` or `WithGroupSearch` as well — see
[groups.md](groups.md).

## Timing

```go
httpauth.WithMinimumDuration(100 * time.Millisecond)
```

A search that matches nothing returns sooner than a search that matches and
then binds, and that difference is measurable over a network — which makes
it an account-enumeration oracle that no amount of collapsing error
messages will close.

Padding every answer to a floor moves the difference below the noise of the
network in front of it. It is not a constant-time guarantee, and nothing
built on a directory round trip can be. Pick a value above your directory's
typical login latency; 100ms is a reasonable place to start.

## Skipping requests

```go
httpauth.WithSkip(func(r *http.Request) bool {
    return r.URL.Path == "/healthz"
})
```

For endpoints mounted behind the same middleware that should not require a
login. Not available in the Fiber adapter, which has no `*http.Request`;
use Fiber's routing instead.

## Basic auth and caching

HTTP Basic sends the credential on every request. A browser hitting a page
with thirty assets behind the same middleware is thirty binds against the
directory.

This is the case the cache exists for:

```go
ldapauth.WithCache(30 * time.Second),
ldapauth.WithNegativeCache(5 * time.Second),
```

and, within a process, identical logins arriving at once are collapsed into
one round trip regardless. See [production.md](production.md) for what the
cache costs and [security.md](security.md) for what it stores.

## Behind a reverse proxy

If something in front of you has already authenticated the request — a
SAML gateway, an OAuth proxy, mTLS at the edge — you do not want this
middleware at all. You want the attributes and groups for a user whose
identity is already established:

```go
identity, err := auth.Lookup(ctx, usernameFromTrustedHeader)
```

`Lookup` needs a service account and returns `ErrUserNotFound` for a
missing user, because the caller already knows who they are asking about
and there is no oracle to protect.

The header has to be trustworthy. A proxy that forwards a client-supplied
`X-Remote-User` unchanged is a proxy that lets anybody be anybody.
