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
  ├── principal mapper   principal.go      entry → Identity
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

## Why so many interfaces

`New` returns a `*Client`; `Authenticate` returns an `Identity`; groups
come from a `GroupResolver`, outcomes go into a `Cache`, connections come
from a `Dialer`.

None of that is generality for its own sake. Each one is a decision that a
real deployment eventually needs to make differently, and each one was
otherwise going to arrive as a feature request that could only be answered
by adding another option:

- somebody's user type has a tenant on it
- somebody's groups live in an entitlements service
- somebody's replicas want to share a cache
- somebody's directory is behind a sidecar

The alternative to an interface is an option for each of those, and then an
option for the case the option did not cover. The interface is smaller than
the options it replaces, and it does not have to anticipate anything.

The cost is one indirect call per authentication, against a round trip that
takes milliseconds — measured, in `benchmarks/`, at no change.

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

## The stampede, and where it lives

A cache stops the second identical login from reaching the directory. It
does nothing about the ninety-nine that arrive before the first one has
finished, which is exactly the shape of HTTP Basic auth in front of a
chatty API.

So requests that miss the cache go through a single-flight: one call to the
directory, and every other caller waits on it and is handed a clone. It is
only wired up when caching is enabled, because without a cache every
request is meant to reach the directory.

Sharing is safe because the key already covers the whole credential. Two
callers that collapse into one are two callers who presented exactly the
same username and password.

## Where the standard library was enough

`log/slog` for logging. `crypto/hmac` for cache keys. `container/list` for
the cache's eviction order. `math/rand/v2` for jitter. `net/http` for the
middleware, including in the Fiber adapter, where a Basic header is handed
to net/http's parser rather than parsed again. None of these cost a
dependency, and the one dependency that does exist is the one that speaks
the protocol.

The same rule points the other way, at go-ldap. The escaping is
`ldap.EscapeFilter` and `ldap.EscapeDN`; scope and dereference validation
ask `ldap.ScopeMap` and `ldap.DerefMap` what they know; retriable result
codes go through `ldap.IsErrorAnyOf`; the fake's scope matching goes
through `ldap.ParseDN` and `DN.AncestorOfFold`. A second implementation of
any of those would be a second thing to keep correct. The package's fuzz
targets assert the property rather than the implementation, so they keep
working whoever provides it.

`Metrics` is an interface rather than an import for the same reason. A
Prometheus adapter is twenty lines on the caller's side, and those twenty
lines are cheaper than everyone who imports this package also importing a
metrics library.

## Related reading

- [security.md](security.md) — the invariants and why each one exists
- [strategies.md](strategies.md) — choosing between the two bind strategies
- [production.md](production.md) — the knobs that matter under load
