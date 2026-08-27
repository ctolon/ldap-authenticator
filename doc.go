// Package ldapauth authenticates users against an LDAP directory.
//
// It sits between go-ldap, which speaks the protocol and leaves every
// decision to you, and the framework-coupled login libraries, which make
// every decision and bring a web framework with them. This package makes
// the decisions that are not really decisions — an empty password is never
// sent, a username is never concatenated into a filter, a pooled
// connection is never rebound as a user — and leaves the rest as options
// with defaults you can live with.
//
// Its only dependency is github.com/go-ldap/ldap/v3. HTTP middleware lives
// in separate modules under contrib/, so importing this package never puts
// a web framework in your build graph.
//
// # Getting started
//
// Build one authenticator at startup and share it. It is safe for
// concurrent use and it owns the connection pool.
//
//	auth, err := ldapauth.New(
//	    ldapauth.WithURL("ldaps://dc1.corp.example:636"),
//	    ldapauth.WithDirectBind("uid={{username}},ou=people,dc=corp,dc=example"),
//	)
//	if err != nil {
//	    return err
//	}
//	defer auth.Close()
//
//	identity, err := auth.Authenticate(ctx, username, password)
//
// The error tells you which of two things happened, and that is nearly all
// the branching a caller needs:
//
//	switch {
//	case err == nil:                                       // authenticated
//	case errors.Is(err, ldapauth.ErrInvalidCredentials):   // 401
//	default:                                               // 503
//	}
//
// # The seams
//
// [New] returns a [*Client], which implements [Authenticator]. Everything
// built on top of an authenticator should depend on that interface rather
// than on the type, so that a test can substitute a fake and a deployment
// can wrap the real one.
//
// [Client.Authenticate] returns an [Identity], and [Principal] is the
// implementation this package produces. Most programs will never name the
// interface: they take what they are given and read it. The programs that
// do name it are the ones supplying their own user type through
// [WithPrincipalMapper], and the reason the return is an interface at all.
//
// Five more interfaces exist for the same reason, each with a working
// default, each replaceable one at a time:
//
//	Dialer           where connections come from       WithDialer
//	Cache            where outcomes are remembered     WithCacheStore
//	PrincipalMapper  what an authentication produces   WithPrincipalMapper
//	GroupResolver    where groups come from            WithGroupResolver
//	Metrics          where the numbers go              WithMetrics
//
// None of them has to be thought about to use this package, and none of
// them costs a dependency.
//
// # The two strategies
//
// A deployment binds one of two ways, and which one is available is a
// question about the directory, not about taste.
//
//	                 direct bind              search then bind
//	round trips      one                      three
//	needs            a DN derivable from      a service account that
//	                 the username             may read the user tree
//	set up with      WithDirectBind           WithUserSearch +
//	                                          WithServiceAccount
//
// Direct bind formats the username into a DN template and binds. Use it
// when users live in one subtree and log in with the attribute that names
// their entry. It needs no privileged account, and with no service account
// configured it reads attributes and groups over the user's own freshly
// bound connection.
//
// Search then bind has a service account find the entry first. Use it when
// users are spread across subtrees, or log in with something that is not
// part of their DN — an email address, an employee number.
//
// # What happens on a login
//
//	Authenticate
//	  │
//	  ├── reject empty username, empty password, control characters
//	  ├── cache lookup (off by default)
//	  ├── coalesce with any identical login already in flight
//	  ├── retry loop (retriable failures only, never a rejected password)
//	  │     │
//	  │     ├── dial: URL list, failover, TLS or StartTLS
//	  │     ├── bind: the user, on a connection of their own
//	  │     ├── read: attributes, over the pool or the user's connection
//	  │     └── groups: memberOf, a group search, or the AD chain rule
//	  │
//	  └── Identity
//
// # Guarantees
//
//   - A bind is never issued with an empty password, and the request is
//     refused before a connection is opened. RFC 4511 makes a zero-length
//     password an unauthenticated bind, which a conforming server answers
//     with success. go-ldap refuses to send one as well; this package
//     refuses sooner, and with an error the caller can branch on.
//   - Every value spliced into a filter is escaped for RFC 4515 — the ones
//     that are themselves distinguished names included — and every value
//     spliced into a DN is escaped for RFC 4514. There is no API through
//     which an unescaped value can be interpolated.
//   - A wrong password and an unknown user return the same error, so a
//     login form built on this package cannot become an account
//     enumeration oracle by forgetting to collapse them.
//   - A pooled connection is bound as the service account and is never
//     rebound as a user. The user's bind gets a connection of its own,
//     which is closed afterwards.
//   - A rejected credential is never retried, so this package cannot walk
//     an account into a lockout policy.
//   - Plaintext ldap:// is refused unless StartTLS is configured or
//     WithInsecureNoTLS is passed explicitly.
//   - No password is ever logged, and no attribute value is either.
//
// # Concurrency
//
// An Authenticator is safe for concurrent use by any number of goroutines.
// Authenticate honours its context for the whole call, retries included,
// and every wait — the dial, the pool checkout, the backoff — is
// selectable against it. A Principal belongs to whoever received it: the
// authenticator keeps no reference and a cached one is served as a copy.
//
// Close is idempotent. Calls already in flight are not interrupted; their
// connections are closed as they are released.
//
// # Groups
//
// Group resolution is off by default, because it costs a round trip and
// not every application needs it. When you turn it on, pick the source
// that matches the directory:
//
//	WithMemberOfGroups          free; needs the memberOf attribute
//	WithGroupSearch             one search; works anywhere
//	WithActiveDirectoryGroups   one search, transitive; AD only
//
// Nested groups walked client-side are bounded twice, by a configured
// depth and by a visited set, because directories will happily let two
// groups contain each other.
//
// # Caching
//
// Caching is off by default and should stay off unless something in front
// of this package re-authenticates the same credentials faster than the
// directory can absorb — HTTP Basic auth on a chatty API being the usual
// reason. What is cached is the outcome, keyed by a keyed hash of the
// username and password; no password and nothing reversible into one is
// stored, and the [Cache] implementation never sees a credential. What it
// costs is a window during which a disabled account still works, and
// [MaxCacheTTL] caps that window at five minutes.
//
// With caching on, identical logins arriving at the same time are
// collapsed into one round trip. The cache absorbs the second and later
// attempts once the first has finished; coalescing is what closes the
// window before that, which is the window a stampede actually lives in.
//
// # Several replicas
//
// Nothing here is shared between processes unless you share it. Each
// replica has its own pool, its own failover state, and its own cache
// secret — which means, by default, its own cache. To share one, give
// every replica the same [WithCacheSecret] and a [WithCacheStore] that
// points at the same place; without the shared secret the keys differ and
// the shared cache silently never hits.
//
// Two things are worth knowing about running many of these at once. The
// retry backoff is fully jittered, so a fleet that lost its directory at
// the same instant does not come back at the same instant. And
// [FailoverInOrder], the default, sends every replica to the same server
// first — which is usually what you want, and is what [FailoverRandom]
// exists to stop when it is not.
//
// # Testing
//
// The ldaptest package is an in-memory directory with a real filter
// parser, real scopes, and faithful bind semantics — including the
// empty-password behaviour, so a test that asserts this package never
// sends one is asserting something. Point an authenticator at it with
// [WithDialer] and no server is needed.
//
// # Errors
//
// Every error wraps a sentinel, so errors.Is reaches it whatever the
// detail. Failures that got as far as the protocol also carry an
// [AuthError] with the step, the server, the LDAP result code, and — when
// the directory said — a [RejectionReason] explaining why it refused.
//
// The reason is for your log and your audit trail, never for a response
// body: Authenticate returns [ErrInvalidCredentials] for a wrong password,
// an unknown user, an expired password and a disabled account alike,
// because a caller that could tell them apart is an account enumeration
// oracle. [ReasonFor] gets it without a type assertion.
//
// # Enterprise directories
//
// Three things that only come up on a real one, each with its own section
// in the documentation:
//
// [WithReferralPolicy] decides what happens when a multi-domain forest
// answers a search with "not in this partition, try over there". Following
// the referral is not on offer — it would mean presenting the service
// account's password to a host the directory named.
//
// [WithLockoutProtection] refuses an account locally after too many recent
// failures, so that the attempts never reach the directory's own lockout
// counter. Anybody who knows a username can otherwise lock that account
// out by getting the password wrong five times.
//
// [NewReloadable] swaps the whole client, which is how the service account
// password is rotated without restarting the process.
package ldapauth
