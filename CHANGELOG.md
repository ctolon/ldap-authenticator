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

### Fixed before release

A pre-release audit found eight defects. None of them shipped, but they are
listed because the reasoning that produced them is worth writing down.

**A username could widen a group filter, and that was an authorisation
bypass.** Placeholders holding a distinguished name were spliced into
search filters unescaped, on the reasoning that a DN is structure rather
than a value and that escaping would corrupt its commas. Both halves were
wrong: `ldap.EscapeFilter` leaves commas alone, and under a direct bind the
user's DN is built from the username. A username of `x*` produced
`(member=uid=x*,ou=people,...)`, which is a prefix match rather than a
membership test, and it handed the caller every group containing anybody
whose DN started the same way. Every placeholder in a filter is now
escaped, with no exceptions.

**LDAP operations could outlive the caller.** go-ldap's operations are
synchronous and take no context, so a cancelled request kept a goroutine
and a pool slot until the operation timeout — or, with no operation timeout
configured, indefinitely. Each operation now runs with the smaller of the
operation timeout and the caller's remaining deadline, and is raced against
cancellation; a connection with an abandoned operation on it is closed
rather than reused.

**Failover only noticed servers that refused a connection.** A directory
that accepted TCP, completed a TLS handshake, and then could not take a
bind was never marked down, so every login kept choosing it first. Any
retriable failure now starts the cooldown. A rejected credential does not,
because a wrong password says nothing about the server.

**The pool never reached its idle floor.** Warming acquired and released a
connection `minIdle` times, which opens one connection and hands it round
in a circle. It now holds them until they are all open, and the reaper puts
the floor back after closing anything that aged out.

**Closing one client emptied every replica's cache.** `Close` invalidated
the cache, which for a shared store meant one process's shutdown throwing
away everybody's entries — and blocking on a round trip to do it. It now
leaves the cache alone.

**Oversized JSON logins were truncated rather than rejected**, so a valid
object in the first 64 KiB was accepted with anything at all behind it; a
body carrying a second object after the credentials was accepted too.

**Multipart logins did not work at all.** `ParseForm` does not parse a
multipart body; every field came back empty and the login failed as though
the password were wrong.

**The Gin and Echo adapters ignored two options they documented** —
`WithSkip` and `WithMaxBodyBytes` — which made "one shared policy, no drift
between adapters" untrue in the place it was load-bearing.

Two more things changed as a result. `Metrics` is frozen for the 1.x line
rather than growing methods that only implementations embedding
`NoopMetrics` would survive; and the release workflow pins its checkout to
the tag being released, passes that tag through the environment rather than
into a shell, and tags the contrib modules at the root tag's commit instead
of at whatever `HEAD` had become.

### Security

The invariants are listed in `SECURITY.md` and each has a test named after
what it protects. The load-bearing ones: an empty password is refused
before a connection is opened; every interpolated value is escaped for the
grammar it lands in; a wrong password and an unknown user are
indistinguishable to the caller; a pooled connection is never rebound as a
user; a rejected credential is never retried; and no password reaches a log
record, an error message, or a cache.

Eleven fuzz targets assert those as properties rather than as outputs,
including three that drive the whole package end to end against a directory
that parses filters and DNs for real: no username may authenticate as
somebody it is not, none may add a term or a wildcard to the user search,
and none may widen a group filter.

The integration suite runs against a real OpenLDAP over plaintext, LDAPS
and StartTLS, verifying against a certificate authority this repository
generates — and asserting that the wrong CA and the wrong hostname are both
refused, so that the TLS tests cannot pass the way `InsecureSkipVerify`
would let them.

[Unreleased]: https://github.com/ctolon/ldap-authenticator/commits/main
