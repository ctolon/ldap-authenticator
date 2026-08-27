# Design

## The shape of the problem

Authenticating against LDAP is three or four round trips and about fifteen
decisions. The round trips are easy. The decisions are where deployments go
wrong, and most of them are not really decisions at all — there is a right
answer and a wrong one, and the wrong one is usually the one that is easier
to write.

This library takes the decisions that have a right answer and makes them.
Everything else is an option.

## Layers

```text
Authenticator            authenticator.go  orchestration
  ├── strategy           strategy.go       direct bind | search then bind
  ├── group resolver     groups.go         memberOf | search | AD chain
  ├── attribute mapper   principal.go      entry → Principal
  ├── cache              cache.go          opt-in, keyed by HMAC
  ├── pool               pool.go           service-account connections
  ├── failover           failover.go       URL order and health
  └── dialer             dial.go           TLS, StartTLS, timeouts
                                             ↓
                              github.com/go-ldap/ldap/v3
```

The only file that touches the wire is `dial.go`. Everything above it talks
to `Conn`, a five-method interface that `*ldap.Conn` already satisfies.

That interface is why the test suite needs no server. It is also why the
package is insulated from go-ldap's own `Client` interface, which is large
and grows: a method added there is not a method this package has to care
about.

## Why the connection interface is narrow

`ldap.Client` has more than twenty methods. This package uses five. Naming
those five and no more means the fake in `ldaptest` is a hundred lines
rather than a thousand, that a caller can supply their own transport
without implementing operations the package will never call, and that a
release of go-ldap that adds a method cannot break anybody's fake.

## Why the pool holds only the service identity

A connection pool that handed out connections bound as whoever last used
them would be a pool that leaks identity between requests. The searches the
next request makes would run with the previous user's permissions.

So the pool holds the service identity and nothing else. A user's bind gets
a connection of its own, which is closed rather than pooled. That costs one
connection per login, which is the correct price.

The consequence worth knowing: under direct bind with no service account,
there is no pool at all, and attribute and group reads happen over the
user's own freshly bound connection. That is what makes a service-account-free
deployment possible, and it means those reads run with the user's own
permissions.

## Why one attempt has no branches

`Authenticate` does not know which strategy is configured. It calls into
one internal shape — given a username and a password, produce the DN that
was authenticated and, if anything read it, the entry — and everything
after that is identical.

That is what keeps retry, caching, metrics, and error wrapping from having
two versions that drift apart. There is exactly one place in the package
that branches on strategy, and it is three lines long.

## Errors

Every error wraps a sentinel, so `errors.Is` reaches it. Failures that got
as far as the protocol also carry an `*AuthError` with the step, the
server, and the LDAP result code, which `errors.As` will find.

The deliberate flattening: a wrong password and an unknown user both come
back as `ErrInvalidCredentials`. A caller who could tell them apart would
be an enumeration oracle for anyone who can reach them, and every login
form built on this package would have to remember to collapse the two.
`Lookup` does distinguish them, because its caller already knows who they
are asking about.

## Why templates instead of format strings

```go
ldapauth.WithDirectBind("uid={{username}},ou=people,dc=corp,dc=example")
```

A format string invites `fmt.Sprintf`, and `fmt.Sprintf` does not escape.
A template that is parsed at construction gets three things a format string
does not: the placeholder names are validated at startup, so a typo is a
startup failure rather than a failed login; each placeholder is escaped for
the grammar it lands in, so a username is escaped as a filter value and a
DN is spliced verbatim; and there is no exported path that interpolates
without escaping.

A single `%s` is still accepted, because most LDAP configuration in the
world is written that way and refusing it would buy nothing.

## Where the standard library was enough

`log/slog` for logging. `crypto/hmac` for cache keys. `container/list` for
the cache's eviction order. `math/rand/v2` for jitter. `net/http` for the
middleware. None of these cost a dependency, and the one dependency that
does exist is the one that speaks the protocol.

`Metrics` is an interface rather than an import for the same reason. A
Prometheus adapter is twenty lines on the caller's side, and those twenty
lines are cheaper than everyone who imports this package also importing a
metrics library.

## Related reading

- [security.md](security.md) — the invariants and why each one exists
- [strategies.md](strategies.md) — choosing between the two bind strategies
- [production.md](production.md) — the knobs that matter under load
