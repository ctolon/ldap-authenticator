# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-08-27

A review of the 1.0 release asked nine questions about running this in an
enterprise directory. Five of them wanted code; the rest wanted the library
to be honest about where its responsibility ends, and are answered in the
documentation.

### Added

**Why the directory refused.** `AuthError.Reason` carries a typed
`RejectionReason` — expired password, disabled account, locked account,
logon-hour restriction, and the rest — read from Active Directory's data
code, which it puts in the text of an otherwise generic error. On OpenLDAP
and 389 Directory Server the same information arrives through the password
policy control, with the new `WithPasswordPolicyControl()`.

`Authenticate` still returns `ErrInvalidCredentials` for every one of them.
That is the point: a login form that could tell "password expired" from
"wrong password" is a slower account enumeration oracle, but it is still
one. The reason is for the log line, the audit trail, and the metric label,
and `ReasonFor(err)` gets it without a type assertion. `Actionable()`
reports whether trying again could help, which is the distinction a help
desk cares about.

**Referrals.** A search answered with referrals and no entries used to be
indistinguishable from "no such user" — which, on a multi-domain Active
Directory forest, is the most confusing way for a base DN to be pointing at
the wrong partition. It is now logged, and `WithReferralPolicy(ReferralFail)`
turns it into `ErrReferral` with the URLs on the error.

Following a referral is still not on offer, and that is a decision: it
means opening a connection to a host the directory named and presenting the
service account's password to it. Use the Global Catalog, or one
authenticator per domain. See docs/directories.md.

**Lockout protection.** `WithLockoutProtection(attempts, window, cooldown)`
refuses an account locally after too many recent failures, so the attempts
never reach the directory's own lockout counter. A directory that locks an
account after five failures is a directory where anybody who knows a
username can lock that account out; this package already refused to make
that worse by retrying, and now it declines to be the instrument. Attempts
served from the cache do not count and are not blocked, so a user who
logged in recently keeps working while somebody guesses at their username.

**`Reloadable`.** The service account password is read once, and rotating
it means building a new `Client` and swapping the pointer. This is that,
with the ordering that everybody gets wrong done right: `Replace` hands
back the old `Client` so it is closed *after* the swap rather than before.
`examples/reloading` runs a rotation under load and counts the failures;
there are none.

**`WithCacheUsernameHashing()`.** The cache key already hides the
credential, but the username travelled beside it in the clear, because
`InvalidateUser` has to find an account's entries without knowing the
password — so a shared or backed-up store held a list of who had logged in
recently. With this, it holds a keyed hash instead, and invalidation still
works.

### Changed

- `Status` in `httpauth` maps `ErrTooManyAttempts` to 429. The credentials
  were never tried, so 401 would be a lie.
- An `*AuthError` is no longer wrapped in another `*AuthError`. It read
  correctly and lost information: `errors.As` stops at the outermost match,
  so a `Reason` or a `Referrals` set deeper down was unreachable.
- A cache secret shorter than 32 bytes is logged as a warning at startup.
  Sixteen remains the hard floor.
- `Stats` reports `BlockedAccounts`.
- The fuzz gate caps its workers at eight rather than one per core. On a
  large machine the uncapped count starved the coordinator, and the run
  failed with `context deadline exceeded` — a gate that fails because the
  machine was busy is a gate people learn to ignore.

### Fixed

- The Go Report Card badge is gone. The service retired; the badge it
  served said so, in place of a grade.
- The Scorecard job no longer asks to publish its result on a push.
  `scorecard-action` publishes only from a scheduled run, so asking on a
  push did nothing except look like it had worked — which is how a badge
  reads "invalid repo path" while every workflow run is green. The push
  run still uploads SARIF to code scanning. The badge is out of the README
  until the first scheduled run produces something for it to show; see
  RELEASING.md.

### Documented

Four questions that wanted an answer rather than a feature.

**Rate limiting and circuit breaking stay outside**, because their policy
is about your traffic rather than about your directory. Both are decorators
over `Authenticator`, which is why that interface exists;
`examples/layered` is a working one of each in about sixty lines, including
the detail that a rejected credential is a working directory and must not
open a breaker.

**Distributed cache invalidation** is a table in docs/production.md now.
With local caches and twenty replicas, disabling an account leaves nineteen
of them letting it in until their TTLs expire. Share the cache, or keep the
TTL short enough not to care. This package will not ship a message bus.

**The shared cache secret is a credential**, and docs/security.md now spells
out what holding it buys: offline credential testing against the cache,
with no bind, no directory, and no failed-login counter. Separate it from
the bind password, use 32 bytes, rotate it, and put an ACL and TLS in front
of the store.

**`InvalidateUser` on the in-memory cache is linear**, which is fine at the
default bound and would not be at a million entries. It is called when
somebody's password changes rather than on the login path, and a credential
cache large enough for the walk to matter has stopped being a cache — but
the `Cache` documentation says so now, for anyone implementing one that
expects to be large.

## [1.0.0] - 2026-08-27

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

[Unreleased]: https://github.com/ctolon/ldap-authenticator/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/ctolon/ldap-authenticator/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ctolon/ldap-authenticator/releases/tag/v1.0.0
