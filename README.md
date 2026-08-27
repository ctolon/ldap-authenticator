# ldap-authenticator

[![CI](https://github.com/ctolon/ldap-authenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/ctolon/ldap-authenticator/actions/workflows/ci.yml)
[![Security](https://github.com/ctolon/ldap-authenticator/actions/workflows/security.yml/badge.svg)](https://github.com/ctolon/ldap-authenticator/actions/workflows/security.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ctolon/ldap-authenticator.svg)](https://pkg.go.dev/github.com/ctolon/ldap-authenticator)
[![Go Report Card](https://goreportcard.com/badge/github.com/ctolon/ldap-authenticator)](https://goreportcard.com/report/github.com/ctolon/ldap-authenticator)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ctolon/ldap-authenticator/badge)](https://scorecard.dev/viewer/?uri=github.com/ctolon/ldap-authenticator)
![Go 1.25+](https://img.shields.io/badge/Go-1.25%2B-00ADD8)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Production LDAP authentication for Go, with one dependency.**

Between `go-ldap`, which speaks the protocol and leaves every decision to
you, and the login libraries that make every decision and bring a web
framework with them. This one makes the decisions that are not really
decisions — an empty password is never sent, a username is never
concatenated into a filter, a pooled connection is never rebound as a user
— and leaves the rest as options with defaults you can live with.

```go
auth, err := ldapauth.New(
    ldapauth.WithURL("ldaps://dc1.corp.example:636"),
    ldapauth.WithDirectBind("uid={{username}},ou=people,dc=corp,dc=example"),
)
if err != nil {
    return err
}
defer auth.Close()

identity, err := auth.Authenticate(ctx, username, password)
switch {
case err == nil:                                     // authenticated
case errors.Is(err, ldapauth.ErrInvalidCredentials): // 401
default:                                             // 503
}
```

The only direct dependency is `github.com/go-ldap/ldap/v3`, and a CI job
fails the build if that ever stops being true.

## Everything is a seam

Seven interfaces, each with a working default, each replaceable on its own.
None of them has to be thought about to use this package, and none of them
costs a dependency.

| | replaces | with |
|---|---|---|
| `Authenticator` | what `New` returns | a fake, or a decorator with a circuit breaker |
| `Identity` | what `Authenticate` returns | your application's own user type |
| `PrincipalMapper` | how an entry becomes an identity | `WithPrincipalMapper` |
| `GroupResolver` | where groups come from | `WithGroupResolver` |
| `Cache` | where outcomes are remembered | `WithCacheStore` |
| `Dialer` | where connections come from | `WithDialer` |
| `Metrics` | where the numbers go | `WithMetrics` |

`Identity`'s accessors are spelled `GetDN`, `GetGroups`, and so on, because
`Principal` carries the same information as exported fields and a field and
a method cannot share a name. It is the spelling go-ldap itself uses for
`ldap.Entry`.

`Principal` is the `Identity` this package produces, and it stays a plain
struct with exported fields — construct one in a test, read it in a
handler:

```go
if p, ok := ldapauth.AsPrincipal(identity); ok {
    log.Println(p.DN, p.Groups, p.Attributes)
}
```

Supply your own when the directory is not the whole story:

```go
ldapauth.WithPrincipalMapper(ldapauth.PrincipalMapperFunc(
    func(m ldapauth.Mapping) (ldapauth.Identity, error) {
        return &user{dn: m.DN, name: m.Username, groups: m.Groups, tenant: tenantOf(m.Entry)}, nil
    },
))
```

## What this is not

It is not a session library. `Authenticate` tells you who the directory
says somebody is; what that becomes — a cookie, a JWT, a row in a table —
is your application's decision, and a library that picked for you would be
a library you had to work around.

It is not a directory client. There is no API here for creating users,
changing passwords, or writing attributes. It reads what it needs to
answer one question.

It is not a framework. The HTTP middleware is opt-in, lives behind its own
import path, and the framework adapters live in separate modules so that
importing this package never puts Gin in your build graph.

## Install

```sh
go get github.com/ctolon/ldap-authenticator
```

And, if you want the framework middleware — each is its own module, with
its own README:

```sh
go get github.com/ctolon/ldap-authenticator/contrib/gin
go get github.com/ctolon/ldap-authenticator/contrib/echo
go get github.com/ctolon/ldap-authenticator/contrib/fiber
```

net/http needs no extra module: `httpauth` is in the root module, because
it needs nothing outside the standard library. See
[docs/http.md](docs/http.md).

## Two strategies, and how to pick

A deployment binds one of two ways, and which one is available is a
question about your directory rather than about taste.

| | direct bind | search then bind |
|---|---|---|
| Round trips | one | three |
| Needs | a DN derivable from the username | a service account that may read the user tree |
| Configure with | `WithDirectBind` | `WithUserSearch` + `WithServiceAccount` |

**Direct bind** when users live in one subtree and log in with the
attribute that names their entry:

```go
ldapauth.WithDirectBind("uid={{username}},ou=people,dc=corp,dc=example")
ldapauth.WithDirectBind("{{username}}@corp.example")  // Active Directory UPN
```

**Search then bind** when users are spread across subtrees, or log in with
something that is not part of their DN — an email address, an employee
number:

```go
ldapauth.WithServiceAccount("cn=readonly,dc=corp,dc=example", os.Getenv("LDAP_SERVICE_PASSWORD")),
ldapauth.WithUserSearch("ou=people,dc=corp,dc=example",
    "(&(objectClass=inetOrgPerson)(uid={{username}}))"),
```

A single `%s` is accepted in place of `{{username}}`, because that is the
spelling most existing LDAP configuration in the world already uses.

## Why the pooled connection is never rebound

The pool holds connections bound as the **service account** and nothing
else. When a user's password is verified, that bind happens on a connection
of its own, which is closed afterwards and never returned to the pool.

This is not an efficiency decision. A pooled connection rebound as a user
carries that user's identity for whichever request picks it up next, and
the searches that request makes run with their permissions. That is an
authorisation bypass built out of an optimisation, and it is the most
common way to get LDAP authentication subtly wrong.

## Groups

Off by default — group resolution costs a round trip and not every
application needs it. Turn on the source that matches the directory:

```go
ldapauth.WithMemberOfGroups()                          // free; needs the memberOf attribute
ldapauth.WithGroupSearch(groupsDN, "(member={{user_dn}})")  // one search; works anywhere
ldapauth.WithActiveDirectoryGroups(groupsDN)           // one search, transitive; AD only
```

```go
if identity.InAnyGroup("developers", "ops") { ... }
```

Nested groups walked from the client are bounded twice, by
`WithNestedGroupDepth` and by a visited set, because a directory will
happily let two groups contain each other. On Active Directory prefer
`WithActiveDirectoryGroups`, which asks the server to do the whole
expansion in one search.

## HTTP

```go
mux.Handle("GET /private", httpauth.BasicAuth(auth,
    httpauth.WithRealm("corp"),
    httpauth.RequireAnyGroup("developers"),
    httpauth.WithMinimumDuration(100*time.Millisecond),
)(handler))

identity := httpauth.MustIdentity(r.Context())
```

The signature is `func(http.Handler) http.Handler`, so it drops into chi,
gorilla/mux, or a bare `ServeMux` unchanged. Gin, Echo, and Fiber get the
same API from their own modules, over the same shared policy, so behaviour
cannot drift between them.

`LoginHandler` reads JSON or form credentials and hands you the identity.
It issues no session and no token, on purpose.

The status mapping is the whole of the error handling most callers need:
401 for wrong or absent credentials, 403 for a failed group requirement,
400 for a request that is not a login, 503 for a directory that could not
answer.

## Guarantees

- **A bind is never issued with an empty password**, and the request is
  refused before a connection is opened. RFC 4511 makes a zero-length
  password an *unauthenticated* bind, which a conforming server answers
  with success.
- **Every value is escaped for the grammar it lands in** — RFC 4515 for
  filters, RFC 4514 for DNs. There is no exported way to interpolate an
  unescaped value.
- **A wrong password and an unknown user are the same error**, so a login
  form built on this package cannot become an account enumeration oracle by
  forgetting to collapse them.
- **A rejected credential is never retried**, so this package cannot walk
  an account into a lockout policy.
- **Plaintext is refused** unless StartTLS is configured or
  `WithInsecureNoTLS` is passed explicitly.
- **No password is logged**, ever, and none is stored: the cache key is an
  HMAC under a random key, and a `Cache` implementation never sees a
  credential.

Each of these has a test named after what it protects. Eleven fuzz targets
assert the properties rather than the outputs — including three that drive
the whole package end to end against a directory that parses filters and
DNs for real: no username may authenticate as somebody it is not, none may
add a term or a wildcard to the user search, and none may widen a group
filter.

## Several replicas

Nothing is shared between processes unless you share it: each replica has
its own pool, its own failover state, and its own cache.

To share a cache, give every replica the same secret and a store that
points at the same place. Without the shared secret each replica derives a
different key for the same login, and the shared cache silently never hits:

```go
ldapauth.WithCache(30*time.Second),
ldapauth.WithCacheSecret(secretFromYourSecretManager),
ldapauth.WithCacheStore(redisCache{client}),   // your ~40 lines
```

Two more things matter at fleet scale. Retry backoff is fully jittered, so
a fleet that lost its directory at the same instant does not come back at
the same instant. And `FailoverInOrder`, the default, sends every replica
to the same server first — usually what you want, and `FailoverRandom` is
there for when it is not.

Within one process, identical logins arriving at the same time are
collapsed into a single round trip, which is the part of a stampede a cache
cannot absorb: the cache only helps once the first attempt has finished.

## Testing without a directory

```go
dir := ldaptest.New(
    ldaptest.User("uid=alice,ou=people,dc=example,dc=com", "s3cret").
        With("uid", "alice").
        With("mail", "alice@example.com"),
)

auth, _ := ldapauth.New(
    ldapauth.WithURL("ldap://in-memory"),
    ldapauth.WithDialer(dir.Dialer()),
    ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),
)
```

`ldaptest` parses filters and applies scopes for real, and models bind
semantics faithfully — including the empty-password behaviour. It is what
this library's own tests run against, which is why it has tests of its own.

## Metrics

`Metrics` is an interface of hooks, not a dependency on a metrics library.
An adapter is about twenty lines:

```go
type promMetrics struct {
    ldapauth.NoopMetrics // embed, so later interface methods do not break you

    attempts *prometheus.CounterVec
    latency  prometheus.Histogram
}

func (m *promMetrics) AuthAttempt(result string, d time.Duration) {
    m.attempts.WithLabelValues(result).Inc()
    m.latency.Observe(d.Seconds())
}

ldapauth.WithMetrics(&promMetrics{...})
```

The `result` values are a closed set, so they are safe as a label.

## Performance

Against the in-memory directory, so these measure the overhead this library
adds on top of a round trip rather than how fast your server is:

```
BenchmarkDirectBind                1542 ns/op    1034 B/op    14 allocs/op
BenchmarkSearchThenBind            4191 ns/op    2559 B/op    42 allocs/op
BenchmarkSearchThenBindWithGroups  5396 ns/op    2639 B/op    60 allocs/op
BenchmarkCachedAuthentication      1535 ns/op     952 B/op    15 allocs/op
```

A real directory answers a bind in single-digit milliseconds, so the
library's overhead is somewhere around a tenth of a percent of a login.
Which is the point of publishing these: they exist so that a regression in
them is visible, not so that they can be quoted.

## Examples

Every one of them runs with no LDAP server installed — they use the
in-memory directory from `ldaptest` — except where a real URL is a flag.

**Getting started**

| | |
|---|---|
| [`examples/basic`](examples/basic) | direct bind, one login |
| [`examples/search-then-bind`](examples/search-then-bind) | service account, pool, health check |
| [`examples/groups`](examples/groups) | all three group sources side by side |
| [`examples/testing`](examples/testing) | what a login does, printed step by step |

**Security**

| | |
|---|---|
| [`examples/escaping`](examples/escaping) | injection, the usual fix, and what this package does instead |
| [`examples/mtls`](examples/mtls) | client certificates and TLS 1.3 |

**Serving HTTP**

| | |
|---|---|
| [`examples/nethttp`](examples/nethttp) | an HTTP server that runs with no directory |
| [`examples/lookup`](examples/lookup) | behind an authenticating proxy, with no password |
| [`contrib/gin/example`](contrib/gin/example) · [`echo`](contrib/echo/example) · [`fiber`](contrib/fiber/example) | the same server, per framework |

**Replacing a seam**

| | |
|---|---|
| [`examples/custom-identity`](examples/custom-identity) | your own user type, from `PrincipalMapper` |
| [`examples/custom-groups`](examples/custom-groups) | groups from an entitlements service, plus the directory's |
| [`examples/cache-store`](examples/cache-store) | a cache shared between replicas |
| [`examples/metrics`](examples/metrics) | a metrics adapter, with no metrics library |

**Operations**

| | |
|---|---|
| [`examples/failover`](examples/failover) | a replica going away, and coming back |

## Documentation

**Start here**

- [docs/strategies.md](docs/strategies.md) — choosing and configuring a bind strategy
- [docs/groups.md](docs/groups.md) — the three sources, nesting, and what each costs
- [docs/http.md](docs/http.md) — middleware, login handlers, status codes, sessions
- [docs/directories.md](docs/directories.md) — what to configure for AD, OpenLDAP, 389ds, FreeIPA

**Reference**

- [docs/configuration.md](docs/configuration.md) — every option, its default, and the thing worth knowing
- [docs/extending.md](docs/extending.md) — the interfaces, and how to replace one
- [docs/testing.md](docs/testing.md) — the in-memory directory, the integration suite, the fuzz targets

**Operating it**

- [docs/production.md](docs/production.md) — timeouts, pools, failover, replicas, and what to alert on
- [docs/troubleshooting.md](docs/troubleshooting.md) — the errors you will actually see

**Understanding it**

- [docs/design.md](docs/design.md) — how the layers fit, and what each one refuses to do
- [docs/security.md](docs/security.md) — the invariants, and the attacks behind them

**Per module**

- [contrib/gin/README.md](contrib/gin/README.md) · [contrib/echo/README.md](contrib/echo/README.md) · [contrib/fiber/README.md](contrib/fiber/README.md)

## Status

1.0. The exported API is stable: it will not break before 2.0, and
`api_test.go` mirrors every exported signature so that a change to one
cannot happen quietly.

What CI proves on every push: the tests pass under the race detector on
Linux, macOS, and Windows, for the root module and all three contrib
modules, on both the oldest toolchain the `go` directive allows and the
newest; the root module and the Gin and Echo adapters compile for sixteen
GOOS/GOARCH pairs, and the Fiber one for fourteen — fasthttp has no wasm
listener; the root module still has exactly one direct dependency; every
exported declaration has a doc comment and every documentation link
resolves; coverage is above its floor; all eleven fuzz targets run; the
workflows lint; and the integration suite passes against a real OpenLDAP
over plaintext, LDAPS and StartTLS, verifying against a real certificate
authority.

Every action is pinned by commit SHA, every job has a timeout and the
least privilege it can do its work with, and no checkout leaves a
credential behind. CodeQL and OpenSSF Scorecard run alongside.

See [CHANGELOG.md](CHANGELOG.md).

## Contributing

```sh
make check
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [RELEASING.md](RELEASING.md), and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Security issues go to the [advisory form](https://github.com/ctolon/ldap-authenticator/security/advisories/new),
not to an issue.

## License

MIT. See [LICENSE](LICENSE).
