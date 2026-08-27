# ldap-authenticator

[![CI](https://github.com/ctolon/ldap-authenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/ctolon/ldap-authenticator/actions/workflows/ci.yml)
[![Security](https://github.com/ctolon/ldap-authenticator/actions/workflows/security.yml/badge.svg)](https://github.com/ctolon/ldap-authenticator/actions/workflows/security.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ctolon/ldap-authenticator.svg)](https://pkg.go.dev/github.com/ctolon/ldap-authenticator)
[![Go Report Card](https://goreportcard.com/badge/github.com/ctolon/ldap-authenticator)](https://goreportcard.com/report/github.com/ctolon/ldap-authenticator)
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

principal, err := auth.Authenticate(ctx, username, password)
switch {
case err == nil:                                     // authenticated
case errors.Is(err, ldapauth.ErrInvalidCredentials): // 401
default:                                             // 503
}
```

The only direct dependency is `github.com/go-ldap/ldap/v3`, and a CI job
fails the build if that ever stops being true.

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

And, if you want the framework middleware:

```sh
go get github.com/ctolon/ldap-authenticator/contrib/gin
go get github.com/ctolon/ldap-authenticator/contrib/echo
go get github.com/ctolon/ldap-authenticator/contrib/fiber
```

net/http needs no extra module: `httpauth` is in the root module, because
it needs nothing outside the standard library.

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
if principal.InAnyGroup("developers", "ops") { ... }
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

principal := httpauth.MustPrincipal(r.Context())
```

The signature is `func(http.Handler) http.Handler`, so it drops into chi,
gorilla/mux, or a bare `ServeMux` unchanged. Gin, Echo, and Fiber get the
same API from their own modules, over the same shared policy, so behaviour
cannot drift between them.

`LoginHandler` reads JSON or form credentials and hands you the principal.
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
  HMAC under a per-process random key.

Each of these has a test named after what it protects, and the escaping has
fuzz targets that assert the property rather than the output.

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
BenchmarkDirectBind                1456 ns/op    1141 B/op    14 allocs/op
BenchmarkSearchThenBind            4788 ns/op    2632 B/op    42 allocs/op
BenchmarkSearchThenBindWithGroups  5872 ns/op    2709 B/op    58 allocs/op
```

A real directory answers a bind in single-digit milliseconds, so the
library's overhead is somewhere around a tenth of a percent of a login.
Which is the point of publishing these: they exist so that a regression in
them is visible, not so that they can be quoted.

## Examples

| | |
|---|---|
| [`examples/basic`](examples/basic) | direct bind, one login |
| [`examples/search-then-bind`](examples/search-then-bind) | service account, pool, health check |
| [`examples/groups`](examples/groups) | all three group sources side by side |
| [`examples/mtls`](examples/mtls) | client certificates and TLS 1.3 |
| [`examples/nethttp`](examples/nethttp) | an HTTP server that runs with no directory |
| [`examples/testing`](examples/testing) | what a login does, printed step by step |
| [`contrib/*/example`](contrib) | Gin, Echo, and Fiber, each runnable as-is |

## Documentation

- [docs/design.md](docs/design.md) — how the layers fit, and what each one refuses to do
- [docs/security.md](docs/security.md) — the invariants, and the attacks behind them
- [docs/strategies.md](docs/strategies.md) — choosing and configuring a bind strategy
- [docs/groups.md](docs/groups.md) — the three sources, nesting, and what each costs
- [docs/production.md](docs/production.md) — timeouts, pools, failover, and what to alert on
- [docs/troubleshooting.md](docs/troubleshooting.md) — the errors you will actually see
- [docs/testing.md](docs/testing.md) — the in-memory directory and the integration suite

## Status

Pre-1.0. The API is settled enough to build on and the invariants are not
going to move, but a minor version may still break a signature — see
[CHANGELOG.md](CHANGELOG.md), where anything that does is listed under
`### Breaking`.

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
