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
//	principal, err := auth.Authenticate(ctx, username, password)
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
//	  ├── retry loop (retriable failures only, never a rejected password)
//	  │     │
//	  │     ├── dial: URL list, failover, TLS or StartTLS
//	  │     ├── bind: the user, on a connection of their own
//	  │     ├── read: attributes, over the pool or the user's connection
//	  │     └── groups: memberOf, a group search, or the AD chain rule
//	  │
//	  └── Principal
//
// # Guarantees
//
//   - A bind is never issued with an empty password, and the request is
//     refused before a connection is opened. RFC 4511 makes a zero-length
//     password an unauthenticated bind, which a conforming server answers
//     with success. go-ldap refuses to send one as well; this package
//     refuses sooner, and with an error the caller can branch on.
//   - Every value spliced into a filter is escaped for RFC 4515, and every
//     value spliced into a DN for RFC 4514. There is no API through which
//     an unescaped value can be interpolated.
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
// username and password under a per-process random key; no password and
// nothing reversible into one is stored. What it costs is a window during
// which a disabled account still works, and [MaxCacheTTL] caps that window
// at five minutes.
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
// [AuthError] with the step, the server, and the LDAP result code, which
// errors.As will find.
package ldapauth
