# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release. An LDAP authenticator whose only direct dependency is
`github.com/go-ldap/ldap/v3`, with the framework integrations kept in
separate modules so that importing it never puts a web framework in your
build graph.

It goes out at 1.0 rather than at 0.1 because the API is settled and the
guarantees are the point: a version number that invites people to expect
breakage is the wrong signal for a library whose job is to be the thing
between a login form and a directory.

### Added

**Both bind strategies.** `WithDirectBind` formats the username into a DN
template and binds — one round trip, no service account. `WithUserSearch`
plus `WithServiceAccount` searches for the entry first and then binds as
the DN the search returned, for directories where the DN cannot be derived
from the username. The user's bind always gets a connection of its own; the
pool holds the service identity and only the service identity.

**Group resolution, three ways.** `WithMemberOfGroups` reads memberships
off the user's own entry at no extra round trip. `WithGroupSearch` searches
the group tree, which works on any directory. `WithActiveDirectoryGroups`
uses the `LDAP_MATCHING_RULE_IN_CHAIN` matching rule so that Active
Directory computes transitive membership itself. Client-side nesting is
bounded by both a configured depth and a visited set, because directories
will happily let two groups contain each other.

**Interfaces at every seam.** `New` returns a `*Client` implementing
`Authenticator`; `Authenticate` returns an `Identity`, of which `Principal`
is the shipped implementation. `PrincipalMapper`, `GroupResolver`, `Cache`,
`Dialer`, and `Metrics` each have a working default and can be replaced one
at a time, so a deployment can supply its own user type, resolve groups
from somewhere that is not the directory, share a cache between replicas,
or route connections through something this package cannot dial — without
any of them costing a dependency.

**Connections that survive production.** An ordered URL list with failover
and a failure cooldown, a bounded connection pool with health probes,
maximum lifetime and idle time, retry with full-jitter backoff, and
timeouts at every layer — dial, operation, and whole request. Every wait is
selectable against the caller's context, and against shutdown.

**TLS, configured or explicitly declined.** `ldaps://` and StartTLS, custom
root CAs, client certificates for mutual TLS, a minimum version of TLS 1.2,
and a refusal to speak plaintext unless `WithInsecureNoTLS` is passed.

**Optional caching, with the stampede closed.** Off by default. When on,
outcomes are keyed by an HMAC of the username and password, capped at a
five-minute TTL, with a shorter negative TTL that stops a client looping on
a stale password from reaching the directory often enough to lock the
account out. Identical logins arriving at once are collapsed into a single
round trip — the part of a stampede a cache cannot absorb, because the
cache only helps once the first attempt has finished. `WithCacheSecret`
and `WithCacheStore` let several replicas share one cache.

**Observability without dependencies.** `WithLogger` takes a `*slog.Logger`
from the standard library, and `Metrics` is an interface of hooks rather
than an import of a metrics library. Neither ever sees a password.

**`httpauth`**, in the root module because it needs nothing but the
standard library: `BasicAuth` middleware with the `func(http.Handler)
http.Handler` shape every net/http router expects, a `LoginHandler` that
reads JSON or form credentials, group requirements, and response padding to
blunt user-enumeration timing.

**Framework modules.** `contrib/gin`, `contrib/echo`, and `contrib/fiber`,
each a separate module wrapping the same shared policy so that behaviour
cannot drift between them.

**`ldaptest`**, an in-memory directory with a real filter parser, real
scopes, and faithful bind semantics — including the empty-password
behaviour, so that a test asserting this library never sends one is
asserting something.

### Security

The invariants are listed in `SECURITY.md` and each has a test named after
what it protects. The load-bearing ones: an empty password is refused
before a connection is opened; every interpolated value is escaped for the
grammar it lands in; a wrong password and an unknown user are
indistinguishable to the caller; a pooled connection is never rebound as a
user; a rejected credential is never retried; and no password reaches a log
record, an error message, or a cache.

Ten fuzz targets assert those as properties rather than as outputs,
including two that drive the whole package end to end against a directory
that parses filters and DNs for real and require that no username, however
constructed, authenticates as somebody it is not.

[Unreleased]: https://github.com/ctolon/ldap-authenticator/commits/main
