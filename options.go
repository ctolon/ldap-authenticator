package ldapauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ctolon/ldap-authenticator/internal/backoff"
)

// An Option configures the authenticator. Options are applied in the order
// they are given and are validated as they are applied, so New reports a
// bad value with the name of the option that carried it rather than as a
// mysterious failure on the first login.
//
// Every option that takes a duration treats a negative value as an error
// and zero as "no limit", except where the doc comment says otherwise.
type Option func(*config) error

// ---- servers and transport ------------------------------------------------

// WithURL sets the directory URL. Calling it more than once appends, so it
// composes with WithURLs; see WithURLs for what more than one URL means.
//
//	ldapauth.WithURL("ldaps://dc1.corp.example:636")
func WithURL(url string) Option {
	return func(c *config) error {
		if strings.TrimSpace(url) == "" {
			return fmt.Errorf("%w: WithURL was given an empty URL", ErrInvalidOption)
		}

		c.urls = append(c.urls, url)

		return nil
	}
}

// WithURLs sets several directory URLs, tried in the order given until one
// accepts a connection. A URL that fails to dial is moved to the back of
// the queue for WithFailoverCooldown, so a replica that is down costs one
// connection timeout rather than one per login.
//
// Failover is between servers holding the same data. It is not a way to
// authenticate against several unrelated directories: whichever server
// answers, the same base DNs and filters are used against it.
func WithURLs(urls ...string) Option {
	return func(c *config) error {
		for _, u := range urls {
			if strings.TrimSpace(u) == "" {
				return fmt.Errorf("%w: WithURLs was given an empty URL", ErrInvalidOption)
			}
		}

		c.urls = append(c.urls, urls...)

		return nil
	}
}

// WithDialer replaces the connection factory.
//
// The dialer this package builds from its own options handles TLS,
// StartTLS, and timeouts. Replace it when the connection has to come from
// somewhere this package cannot reach on its own, and in tests. A custom
// dialer takes over responsibility for TLS: the TLS options are not
// applied to it, and the plaintext check in New is skipped, because there
// is no way for this package to know what your dialer negotiated.
func WithDialer(d Dialer) Option {
	return func(c *config) error {
		if d == nil {
			return fmt.Errorf("%w: WithDialer was given a nil dialer", ErrInvalidOption)
		}

		c.dialer = d
		c.insecureNoTLS = true

		return nil
	}
}

// WithDialTimeout bounds one TCP connect plus TLS handshake. Zero is an
// error here: a dial with no timeout is a goroutine with no end.
func WithDialTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: dial timeout %s is not positive", ErrInvalidOption, d)
		}

		c.dialTimeout = d

		return nil
	}
}

// WithOperationTimeout bounds a single LDAP operation on an established
// connection. Zero means no per-operation limit, leaving only the request
// timeout and the caller's context.
func WithOperationTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d < 0 {
			return fmt.Errorf("%w: operation timeout %s is negative", ErrInvalidOption, d)
		}

		c.operationTimeout = d

		return nil
	}
}

// WithRequestTimeout bounds one whole call to Authenticate or Lookup,
// retries included. It applies only when the caller's context has no
// earlier deadline of its own — a caller who passes a deadline always gets
// the tighter of the two. Zero disables it.
func WithRequestTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d < 0 {
			return fmt.Errorf("%w: request timeout %s is negative", ErrInvalidOption, d)
		}

		c.requestTimeout = d

		return nil
	}
}

// WithFailoverPolicy sets the order in which several servers are tried.
func WithFailoverPolicy(p FailoverPolicy) Option {
	return func(c *config) error {
		if !p.valid() {
			return fmt.Errorf("%w: failover policy %d is not valid", ErrInvalidOption, int(p))
		}

		c.failoverPolicy = p

		return nil
	}
}

// WithFailoverCooldown sets how long a server that failed to dial is tried
// last. Zero disables the memory, so every login pays the timeout of every
// dead server ahead of the live one.
func WithFailoverCooldown(d time.Duration) Option {
	return func(c *config) error {
		if d < 0 {
			return fmt.Errorf("%w: failover cooldown %s is negative", ErrInvalidOption, d)
		}

		c.failoverCooldown = d

		return nil
	}
}

// ---- TLS ------------------------------------------------------------------

// WithTLSConfig sets the TLS configuration wholesale, replacing anything
// the narrower TLS options had set. The value is cloned, so later
// modifications by the caller do not reach the authenticator.
func WithTLSConfig(t *tls.Config) Option {
	return func(c *config) error {
		if t == nil {
			return fmt.Errorf("%w: WithTLSConfig was given a nil config", ErrInvalidOption)
		}

		c.tlsConfig = t.Clone()

		return nil
	}
}

// WithStartTLS upgrades plaintext connections with the RFC 4513 StartTLS
// extended operation before any bind. It is ignored for ldaps:// URLs,
// which are wrapped from the first byte, and for ldapi:// unix sockets.
//
// A StartTLS that the server refuses is a hard failure: the connection is
// closed rather than used unencrypted. There is no downgrade path, by
// design.
func WithStartTLS() Option {
	return func(c *config) error {
		c.startTLS = true

		return nil
	}
}

// WithRootCAs sets the certificate pool used to verify the directory's
// certificate, replacing the system pool.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(c *config) error {
		if pool == nil {
			return fmt.Errorf("%w: WithRootCAs was given a nil pool", ErrInvalidOption)
		}

		c.ensureTLS().RootCAs = pool

		return nil
	}
}

// WithRootCAFile reads one or more PEM certificates from path and uses
// them to verify the directory's certificate, replacing the system pool.
// The file is read once, when the option is applied.
func WithRootCAFile(path string) Option {
	return func(c *config) error {
		pem, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%w: reading root CA file: %w", ErrInvalidOption, err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("%w: root CA file %q contains no PEM certificate", ErrInvalidOption, path)
		}

		c.ensureTLS().RootCAs = pool

		return nil
	}
}

// WithClientCertificate presents a client certificate to the directory,
// for deployments that authenticate the application itself with mutual
// TLS.
func WithClientCertificate(cert tls.Certificate) Option {
	return func(c *config) error {
		if len(cert.Certificate) == 0 {
			return fmt.Errorf("%w: WithClientCertificate was given an empty certificate", ErrInvalidOption)
		}

		tc := c.ensureTLS()
		tc.Certificates = append(tc.Certificates, cert)

		return nil
	}
}

// WithClientCertificateFiles loads a PEM certificate and key from disk and
// presents them to the directory. The files are read once, when the option
// is applied; rotating them means building a new authenticator, or setting
// GetClientCertificate through WithTLSConfig.
func WithClientCertificateFiles(certFile, keyFile string) Option {
	return func(c *config) error {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("%w: loading client certificate: %w", ErrInvalidOption, err)
		}

		tc := c.ensureTLS()
		tc.Certificates = append(tc.Certificates, cert)

		return nil
	}
}

// WithServerName sets the name verified against the directory's
// certificate. Set it when connecting by IP address, or through a name
// that is not the one on the certificate.
func WithServerName(name string) Option {
	return func(c *config) error {
		if name == "" {
			return fmt.Errorf("%w: WithServerName was given an empty name", ErrInvalidOption)
		}

		c.ensureTLS().ServerName = name

		return nil
	}
}

// WithMinTLSVersion sets the minimum TLS version accepted, as one of the
// tls.VersionTLS* constants. The default is TLS 1.2.
func WithMinTLSVersion(version uint16) Option {
	return func(c *config) error {
		switch version {
		case tls.VersionTLS12, tls.VersionTLS13:
		case tls.VersionTLS10, tls.VersionTLS11:
			return fmt.Errorf(
				"%w: TLS versions below 1.2 are not accepted; the directory should be upgraded",
				ErrInvalidOption,
			)
		default:
			return fmt.Errorf("%w: %#x is not a TLS version", ErrInvalidOption, version)
		}

		c.ensureTLS().MinVersion = version

		return nil
	}
}

// WithInsecureSkipVerify accepts any certificate the directory presents.
//
// This turns TLS into encryption without authentication: an attacker who
// can answer for the directory's address can present their own certificate,
// take the bind, and read the password. Use it to get a self-signed lab
// running, and use WithRootCAFile everywhere else.
func WithInsecureSkipVerify() Option {
	return func(c *config) error {
		c.ensureTLS().InsecureSkipVerify = true

		return nil
	}
}

// WithInsecureNoTLS permits a plaintext ldap:// connection with no
// StartTLS upgrade.
//
// A simple bind sends the password as a length-prefixed string with no
// encoding at all. Without this option New refuses such a configuration,
// and the option is named the way it is so that the refusal cannot be
// silenced without leaving evidence in the source.
func WithInsecureNoTLS() Option {
	return func(c *config) error {
		c.insecureNoTLS = true

		return nil
	}
}

// ---- bind strategy --------------------------------------------------------

// WithDirectBind configures the direct-bind strategy: the username is
// substituted into a DN template and bound directly, with no service
// account and no search.
//
//	ldapauth.WithDirectBind("uid={{username}},ou=people,dc=corp,dc=example")
//	ldapauth.WithDirectBind("{{username}}@corp.example")   // Active Directory UPN
//
// The substituted value is escaped as an RFC 4514 attribute value, so a
// username containing a comma names an entry rather than a new DN
// component. A single %s is accepted in place of {{username}}, which is
// the spelling most existing LDAP configuration uses.
//
// Direct bind is one round trip and needs no privileged account, which
// makes it the strategy to prefer when the DN can be derived from the
// username. When it cannot — because users live in several subtrees, or
// log in with an attribute that is not part of their DN — use
// WithUserSearch.
//
// Attributes and groups still need somewhere to be read from. By default
// they are read over the user's own freshly bound connection, so a direct
// bind deployment needs no service account at all; configure
// WithServiceAccount as well if the users themselves may not read their
// own entry.
func WithDirectBind(dnTemplate string) Option {
	return func(c *config) error {
		t, err := parseTemplate(dnTemplate, placeholderUsername)
		if err != nil {
			return fmt.Errorf("WithDirectBind: %w", err)
		}

		c.bindDN = t

		return nil
	}
}

// WithUserSearch configures the search-then-bind strategy: a service
// account searches baseDN for the entry matching filterTemplate, and the
// user's password is then verified by binding as the DN that search
// returned.
//
//	ldapauth.WithUserSearch(
//	    "ou=people,dc=corp,dc=example",
//	    "(&(objectClass=inetOrgPerson)(uid={{username}}))",
//	)
//
// The substituted username is escaped for RFC 4515, so a filter cannot be
// broken out of. {{base_dn}} is also available, and expands to baseDN.
//
// The user bind happens on its own connection, which is closed afterwards
// and never returned to the pool. Rebinding a pooled connection as the
// user would leave that connection carrying the user's identity for
// whichever request picked it up next — the single most common way to
// build an authorisation bypass on top of LDAP.
//
// A search that matches more than one entry is an error, not a race to
// pick the first: see ErrAmbiguousUser.
func WithUserSearch(baseDN, filterTemplate string) Option {
	return func(c *config) error {
		if strings.TrimSpace(baseDN) == "" {
			return fmt.Errorf("%w: WithUserSearch was given an empty base DN", ErrInvalidOption)
		}

		t, err := parseTemplate(filterTemplate, placeholderUsername, placeholderBaseDN)
		if err != nil {
			return fmt.Errorf("WithUserSearch: %w", err)
		}

		c.userBaseDN = baseDN
		c.userFilter = t

		return nil
	}
}

// WithUserSearchScope sets the scope of the user search: ScopeBaseObject,
// ScopeSingleLevel, or ScopeWholeSubtree. The default is the whole
// subtree; narrowing it to a single level is worth doing when the
// directory is flat, because it stops a filter typo from walking the tree.
func WithUserSearchScope(scope int) Option {
	return func(c *config) error {
		if !scopeValid(scope) {
			return fmt.Errorf("%w: %d is not a valid search scope", ErrInvalidOption, scope)
		}

		c.userScope = scope

		return nil
	}
}

// WithDerefAliases sets alias dereferencing for searches, as one of
// ldap.NeverDerefAliases, ldap.DerefInSearching, ldap.DerefFindingBaseObj,
// or ldap.DerefAlways. The default is never: an alias that can redirect a
// user search is an alias that can redirect an authentication.
func WithDerefAliases(deref int) Option {
	return func(c *config) error {
		if !derefValid(deref) {
			return fmt.Errorf("%w: %d is not a valid alias dereferencing mode", ErrInvalidOption, deref)
		}

		c.userDerefAliases = deref

		return nil
	}
}

// WithSearchSizeLimit caps how many entries a search may return. Zero, the
// default, leaves the limit to the server.
func WithSearchSizeLimit(limit int) Option {
	return func(c *config) error {
		if limit < 0 {
			return fmt.Errorf("%w: search size limit %d is negative", ErrInvalidOption, limit)
		}

		c.userSizeLimit = limit

		return nil
	}
}

// WithPagingSize turns searches into paged searches with the given page
// size. Active Directory caps a search at 1000 entries and truncates
// silently past that, so a group search over a large directory needs this
// to see the whole answer. Zero, the default, does not page.
func WithPagingSize(size uint32) Option {
	return func(c *config) error {
		c.pagingSize = size

		return nil
	}
}

// WithServiceAccount sets the credentials used for searching: for the user
// search under WithUserSearch, and for group and attribute lookups under
// either strategy.
//
// The account needs read access to the user and group subtrees and nothing
// more. It never needs to write, and it never needs to read passwords —
// this package verifies a password by binding, never by comparing.
func WithServiceAccount(dn, password string) Option {
	return func(c *config) error {
		if strings.TrimSpace(dn) == "" {
			return fmt.Errorf("%w: WithServiceAccount was given an empty DN", ErrInvalidOption)
		}

		if password == "" {
			return fmt.Errorf(
				"%w: WithServiceAccount was given an empty password, which LDAP would treat as an anonymous bind",
				ErrInvalidOption,
			)
		}

		c.serviceDN = dn
		c.servicePassword = password

		return nil
	}
}

// WithAnonymousServiceBind searches without binding at all, for the rare
// directory that answers anonymous searches. It has to be asked for
// explicitly because a directory that permits anonymous search and a
// deployment that forgot its service account credentials look identical
// from inside this package.
func WithAnonymousServiceBind() Option {
	return func(c *config) error {
		c.anonymousService = true

		return nil
	}
}

// WithReferralPolicy decides what happens when a search comes back with
// referrals and no entries.
//
// A referral is the directory saying "not in this partition, try over
// there". On a single-domain deployment it never happens; on a
// multi-domain Active Directory forest it happens whenever a base DN names
// a partition that does not hold the object — which is a configuration
// mistake that otherwise presents as "no such user", and sends somebody
// hunting for an account that is exactly where it should be.
//
// [ReferralIgnore], the default, treats the answer as empty and logs a
// warning. [ReferralFail] returns [ErrReferral] with the URLs on the
// [AuthError], which is what to use once you are confident your base DNs
// are right.
//
// Neither follows the referral, and that is a decision rather than an
// omission: following one means opening a connection to a host the
// directory named and presenting the service account's password to it.
// Use the Global Catalog for a forest-wide search instead — see
// docs/directories.md.
func WithReferralPolicy(policy ReferralPolicy) Option {
	return func(c *config) error {
		if !policy.valid() {
			return fmt.Errorf("%w: referral policy %d is not valid", ErrInvalidOption, int(policy))
		}

		c.referralPolicy = policy

		return nil
	}
}

// WithPasswordPolicyControl asks for the password policy control on every
// bind, which is how a directory other than Active Directory says *why* it
// refused a credential.
//
// With it, [AuthError.Reason] can distinguish an expired password, a
// locked account, or one that must be changed after a reset, on OpenLDAP,
// 389 Directory Server and anything else implementing
// draft-behera-ldap-password-policy. Active Directory needs nothing here:
// it puts the same information in the error text, and this package reads
// it either way.
//
// It is off by default because it changes what goes on the wire. The
// control is non-critical, so a directory that does not know it ignores
// it, but "adds an unrequested control to every bind" is not a thing to do
// to somebody without asking.
//
// The reason never changes what [Client.Authenticate] returns. It is for
// the log line and the audit trail; see [RejectionReason].
func WithPasswordPolicyControl() Option {
	return func(c *config) error {
		c.passwordPolicyControl = true

		return nil
	}
}

// ---- attributes -----------------------------------------------------------

// WithUsernameAttribute names the attribute read into Principal.Username.
// Without it, Principal.Username is the username as supplied by the
// caller — which is usually what you want, and is the only thing available
// under a direct bind that does no lookup.
func WithUsernameAttribute(name string) Option {
	return func(c *config) error {
		return setAttribute("WithUsernameAttribute", name, &c.usernameAttribute)
	}
}

// WithDisplayNameAttribute names the attribute read into
// Principal.DisplayName, commonly "displayName" or "cn".
func WithDisplayNameAttribute(name string) Option {
	return func(c *config) error {
		return setAttribute("WithDisplayNameAttribute", name, &c.displayNameAttribute)
	}
}

// WithEmailAttribute names the attribute read into Principal.Email,
// commonly "mail" or "userPrincipalName".
func WithEmailAttribute(name string) Option {
	return func(c *config) error {
		return setAttribute("WithEmailAttribute", name, &c.emailAttribute)
	}
}

// WithAttributes asks for further attributes, which arrive in
// Principal.Attributes exactly as the directory returned them. Calling it
// more than once appends.
//
// Ask only for what you use. Every attribute named here is transferred on
// every login, and an attribute you fetch is an attribute you may
// accidentally log.
func WithAttributes(names ...string) Option {
	return func(c *config) error {
		for _, name := range names {
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("%w: WithAttributes was given an empty attribute name", ErrInvalidOption)
			}
		}

		c.extraAttributes = append(c.extraAttributes, names...)

		return nil
	}
}

// ---- groups ---------------------------------------------------------------

// WithMemberOfGroups resolves groups from the user's own entry, reading
// the attribute named by WithMemberOfAttribute ("memberOf" by default).
//
// This is the cheap way: the memberships come back with the user's
// attributes and cost no extra round trip. It needs a directory that
// maintains the attribute — Active Directory always does, OpenLDAP does
// with the memberof overlay configured.
func WithMemberOfGroups() Option {
	return func(c *config) error {
		c.groupSource = GroupsFromMemberOf

		return nil
	}
}

// WithMemberOfAttribute names the attribute holding group memberships on
// the user's entry, and selects the memberOf group source.
func WithMemberOfAttribute(name string) Option {
	return func(c *config) error {
		if err := setAttribute("WithMemberOfAttribute", name, &c.memberOfAttribute); err != nil {
			return err
		}

		c.groupSource = GroupsFromMemberOf

		return nil
	}
}

// WithGroupSearch resolves groups by searching baseDN for entries that
// name the user as a member.
//
//	ldapauth.WithGroupSearch(
//	    "ou=groups,dc=corp,dc=example",
//	    "(&(objectClass=groupOfNames)(member={{user_dn}}))",
//	)
//
// The template may use {{user_dn}}, {{username}}, and {{base_dn}}.
// {{user_dn}} expands to the DN of the authenticated entry. Every
// placeholder is escaped for RFC 4515, the DNs included: a DN in a filter
// is an assertion value, and escaping it leaves its commas and equals
// signs alone while stopping an asterisk in it from widening the match.
//
// Use this on directories with no memberOf overlay, or where memberships
// live on the group rather than on the user — which is the case for
// posixGroup and for groupOfNames without the overlay.
func WithGroupSearch(baseDN, filterTemplate string) Option {
	return func(c *config) error {
		if strings.TrimSpace(baseDN) == "" {
			return fmt.Errorf("%w: WithGroupSearch was given an empty base DN", ErrInvalidOption)
		}

		t, err := parseTemplate(filterTemplate, placeholderUserDN, placeholderUsername, placeholderBaseDN)
		if err != nil {
			return fmt.Errorf("WithGroupSearch: %w", err)
		}

		c.groupBaseDN = baseDN
		c.groupFilter = t
		c.groupSource = GroupsFromSearch

		return nil
	}
}

// WithGroupSearchScope sets the scope of the group search. The default is
// the whole subtree.
func WithGroupSearchScope(scope int) Option {
	return func(c *config) error {
		if !scopeValid(scope) {
			return fmt.Errorf("%w: %d is not a valid search scope", ErrInvalidOption, scope)
		}

		c.groupScope = scope

		return nil
	}
}

// WithGroupNameAttribute names the attribute read as a group's name, "cn"
// by default. It is also what nested resolution reads when it walks from a
// group DN to a group name.
func WithGroupNameAttribute(name string) Option {
	return func(c *config) error {
		return setAttribute("WithGroupNameAttribute", name, &c.groupNameAttribute)
	}
}

// WithGroupDNs reports group DNs in Principal.Groups instead of names.
//
// DNs are unambiguous and names are not: two subtrees may each hold a
// group called "admins", and an authorisation rule written against the
// name cannot tell them apart. Prefer DNs when the group tree is large
// enough for that to be possible.
func WithGroupDNs() Option {
	return func(c *config) error {
		c.groupsAsDN = true

		return nil
	}
}

// WithNestedGroups expands groups that are members of other groups, up to
// WithNestedGroupDepth levels.
//
// It costs round trips: one lookup per group under the memberOf source,
// one search per level under the search source. On Active Directory prefer
// WithActiveDirectoryNestedGroups, which asks the server to do the whole
// expansion in a single search.
func WithNestedGroups() Option {
	return func(c *config) error {
		c.nestedGroups = true

		return nil
	}
}

// WithNestedGroupDepth caps how far nested expansion walks. The default is
// DefaultNestedGroupDepth. The cap is what stops a directory with a
// membership cycle from turning one login into an unbounded walk; the
// expansion also remembers what it has already visited, so the cap is a
// second line of defence rather than the only one.
func WithNestedGroupDepth(depth int) Option {
	return func(c *config) error {
		if depth < 1 {
			return fmt.Errorf("%w: nested group depth %d is below 1", ErrInvalidOption, depth)
		}

		c.nestedGroupDepth = depth
		c.nestedGroups = true

		return nil
	}
}

// WithActiveDirectoryGroups configures group resolution the way Active
// Directory wants it: a search under baseDN using the
// LDAP_MATCHING_RULE_IN_CHAIN matching rule, OID 1.2.840.113556.1.4.1941,
// which has the server compute transitive group membership itself.
//
//	ldapauth.WithActiveDirectoryGroups("OU=Groups,DC=corp,DC=example")
//
// One search returns every group the user is in, directly or through
// nesting, so this is both faster and more complete than walking the
// membership graph from the client. It is worth reaching for whenever the
// directory is AD.
//
// The matching rule is an Active Directory extension. A directory that
// does not implement it answers the search with no entries rather than
// with an error, which is indistinguishable from a user who is in no
// groups — so do not enable this against anything else.
func WithActiveDirectoryGroups(baseDN string) Option {
	return func(c *config) error {
		if strings.TrimSpace(baseDN) == "" {
			return fmt.Errorf("%w: WithActiveDirectoryGroups was given an empty base DN", ErrInvalidOption)
		}

		t, err := parseTemplate(
			"(member:1.2.840.113556.1.4.1941:={{"+placeholderUserDN+"}})",
			placeholderUserDN,
		)
		if err != nil {
			return fmt.Errorf("WithActiveDirectoryGroups: %w", err)
		}

		c.groupBaseDN = baseDN
		c.groupFilter = t
		c.groupSource = GroupsFromSearch
		c.activeDirectoryChain = true
		c.nestedGroups = true

		return nil
	}
}

// ---- connection pool ------------------------------------------------------

// WithPoolSize caps the pooled service-account connections. The pool only
// exists when the configuration searches the directory at all; a direct
// bind with no lookups never builds one.
//
// Size this against the directory's own connection limit, not against your
// request rate: pooled connections are held for the duration of a search,
// which is milliseconds.
func WithPoolSize(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("%w: pool size %d is below 1", ErrInvalidOption, n)
		}

		c.poolSize = n

		return nil
	}
}

// WithPoolMinIdle keeps at least n connections open and bound, so that a
// burst after a quiet period does not pay for n binds. The default is
// zero: connections are opened on demand and closed when they go idle.
func WithPoolMinIdle(n int) Option {
	return func(c *config) error {
		if n < 0 {
			return fmt.Errorf("%w: pool minimum idle %d is negative", ErrInvalidOption, n)
		}

		c.poolMinIdle = n

		return nil
	}
}

// WithPoolMaxLifetime retires a pooled connection after this long,
// however healthy it is. Zero disables retirement.
//
// Keep it well under any idle timeout the directory or a load balancer in
// front of it enforces, and keep it finite: a connection that never
// retires never notices that the load balancer has new backends.
func WithPoolMaxLifetime(d time.Duration) Option {
	return func(c *config) error {
		if d < 0 {
			return fmt.Errorf("%w: pool max lifetime %s is negative", ErrInvalidOption, d)
		}

		c.poolMaxLifetime = d

		return nil
	}
}

// WithPoolMaxIdleTime closes a pooled connection that has gone unused for
// this long. Zero keeps idle connections indefinitely, up to the maximum
// lifetime.
func WithPoolMaxIdleTime(d time.Duration) Option {
	return func(c *config) error {
		if d < 0 {
			return fmt.Errorf("%w: pool max idle time %s is negative", ErrInvalidOption, d)
		}

		c.poolMaxIdleTime = d

		return nil
	}
}

// WithPoolHealthCheck controls whether a pooled connection is probed
// before being handed out. The probe is a Who Am I extended operation,
// which is a round trip; without it, the first search on a connection the
// server has quietly dropped fails instead, and is retried on a fresh one.
//
// The default is on. Turn it off when the round trip matters more than the
// retry, which is to say when the directory is local and the request rate
// is high.
func WithPoolHealthCheck(enabled bool) Option {
	return func(c *config) error {
		c.poolHealthCheck = enabled

		return nil
	}
}

// ---- retry ----------------------------------------------------------------

// WithRetry sets how many times a *retriable* failure is tried again.
//
// Retriable means the failure said nothing about the answer: the
// connection broke, the server was busy, the server was going down.
// Rejected credentials are never retried — a directory with a lockout
// policy counts failed binds, and a library that retried them would turn
// one typo into three strikes.
func WithRetry(attempts int) Option {
	return func(c *config) error {
		if attempts < 0 {
			return fmt.Errorf("%w: retry attempts %d is negative", ErrInvalidOption, attempts)
		}

		c.retryMaxAttempts = attempts

		return nil
	}
}

// WithoutRetry disables retries. Every failure is reported to the caller
// as it happened.
func WithoutRetry() Option {
	return func(c *config) error {
		c.retryMaxAttempts = 0

		return nil
	}
}

// WithRetryBackoff sets the retry delay envelope: the first delay, the cap
// on a single delay, and the growth factor between them. The actual delay
// is drawn uniformly from (0, envelope] — full jitter, because a fleet
// that lost its directory at the same instant should not come back at the
// same instant.
func WithRetryBackoff(base, max time.Duration, multiplier float64) Option {
	return func(c *config) error {
		if base <= 0 {
			return fmt.Errorf("%w: retry base delay %s is not positive", ErrInvalidOption, base)
		}

		if max < base {
			return fmt.Errorf(
				"%w: retry max delay %s is below the base delay %s",
				ErrInvalidOption, max, base,
			)
		}

		if multiplier < 1 {
			return fmt.Errorf("%w: retry multiplier %v is below 1", ErrInvalidOption, multiplier)
		}

		c.backoff = backoff.Policy{Base: base, Max: max, Multiplier: multiplier}

		return nil
	}
}

// WithRetryMaxElapsed caps the total time spent retrying, backoff
// included. A retry that would sleep past the cap is not taken. Zero
// removes the cap, leaving only the attempt count.
func WithRetryMaxElapsed(d time.Duration) Option {
	return func(c *config) error {
		if d < 0 {
			return fmt.Errorf("%w: retry max elapsed %s is negative", ErrInvalidOption, d)
		}

		c.retryMaxElapsed = d

		return nil
	}
}

// ---- cache ----------------------------------------------------------------

// WithCache serves repeat authentications from memory for ttl.
//
// Caching is off by default and should stay off unless something in front
// of this package re-authenticates the same credentials at a rate the
// directory cannot absorb — HTTP Basic auth on a chatty API being the
// usual reason.
//
// What is cached is the *result*, keyed by a keyed hash of the username
// and password; neither the password nor a reversible function of it is
// stored. What it costs is a window during which a disabled account, a
// changed password, or a revoked group still works. MaxCacheTTL caps that
// window at five minutes, and there is no option to raise the cap.
func WithCache(ttl time.Duration) Option {
	return func(c *config) error {
		if ttl <= 0 {
			return fmt.Errorf("%w: cache TTL %s is not positive", ErrInvalidOption, ttl)
		}

		if ttl > MaxCacheTTL {
			return fmt.Errorf(
				"%w: cache TTL %s exceeds the %s ceiling",
				ErrInvalidOption, ttl, MaxCacheTTL,
			)
		}

		c.cacheEnabled = true
		c.cacheTTL = ttl

		return nil
	}
}

// WithNegativeCache serves repeat *failures* from memory for ttl, which is
// what stops a misconfigured client retrying a stale password from
// reaching the directory often enough to lock the account out. The default
// is DefaultNegativeCacheTTL, deliberately much shorter than the positive
// TTL. Zero disables negative caching while leaving positive caching on.
func WithNegativeCache(ttl time.Duration) Option {
	return func(c *config) error {
		if ttl < 0 {
			return fmt.Errorf("%w: negative cache TTL %s is negative", ErrInvalidOption, ttl)
		}

		if ttl > MaxCacheTTL {
			return fmt.Errorf(
				"%w: negative cache TTL %s exceeds the %s ceiling",
				ErrInvalidOption, ttl, MaxCacheTTL,
			)
		}

		c.cacheNegativeTTL = ttl

		return nil
	}
}

// WithCacheStore replaces the in-memory cache with an implementation of
// your own, which is how several replicas share one.
//
//	ldapauth.WithCache(30*time.Second),
//	ldapauth.WithCacheSecret(secretFromYourSecretManager),
//	ldapauth.WithCacheStore(redisCache{client}),
//
// A shared cache needs a shared secret as well. Keys are derived from the
// credential by HMAC under the authenticator's secret, and the default
// secret is drawn from the system CSPRNG at startup — so without
// [WithCacheSecret] every replica derives a different key for the same
// login and the shared cache never hits.
//
// The store never sees a credential: it is handed an opaque key, the
// username, and the outcome. What it must not do is outlive the trust
// boundary the outcome was decided in — a cache shared between two
// services is a cache in which one service's authentication decisions
// become the other's.
//
// # Read the write side before you use this
//
// A Cache is handed a decoded [Identity] and trusted for what it returns.
// The key is an HMAC, so nobody can read an entry without the secret, but
// nothing authenticates the value: anybody who can write to the store can
// put an identity carrying "cn=domain admins" under a key of their choosing,
// and the login that lands on it is authorised as that. This is not a
// theoretical asymmetry — a Redis with no auth on a flat network is the
// normal way it happens.
//
// Prefer [WithSealedCacheStore], which authenticates the value as well as
// the key. Use this option when you need control over the encoding, or
// when [WithPrincipalMapper] gives you an identity this package cannot
// serialise; then treat write access to the store as equivalent to write
// access to the directory, and say so in your threat model.
//
// Caching must be turned on with [WithCache] as well; a store with no TTL
// configured is a configuration error rather than an implicit default.
func WithCacheStore(store Cache) Option {
	return func(c *config) error {
		if store == nil {
			return fmt.Errorf("%w: WithCacheStore was given a nil store", ErrInvalidOption)
		}

		c.cacheStore = store

		return nil
	}
}

// WithSealedCacheStore shares a cache across replicas without trusting
// what is in it.
//
//	ldapauth.WithCache(30*time.Second),
//	ldapauth.WithCacheSecret(secretFromYourSecretManager),
//	ldapauth.WithSealedCacheStore(redisStore{client}),
//
// A [ByteStore] holds bytes, which is what Redis and memcached are. The
// authenticator serialises the identity, seals it with HMAC-SHA-256 under
// the same secret that derives the key, and verifies the seal on the way
// back out. A value that does not verify is a miss: it is logged, counted
// by [Metrics.CacheEvent] under [CacheError], and the directory is asked.
// So a store can lose entries, or be written to by somebody who should not
// be, without ever being able to decide who somebody is.
//
// This is the option to reach for. [WithCacheStore] leaves the value
// unauthenticated and exists for callers who need their own encoding.
//
// Two things it does not carry:
//
//   - [Principal.Extra] is dropped. It holds a value of your type, and
//     JSON would hand it back as a map — so a cached login would differ
//     from an uncached one in a way that only shows up in production.
//   - A custom [Identity] from [WithPrincipalMapper] cannot be encoded at
//     all. The write fails, is logged and counted, and the login proceeds
//     uncached. Use [WithCacheStore] with your own serialisation instead.
//
// The same [WithCacheSecret] must reach every replica, both for the keys
// to match and for the seals to verify. Rotating it invalidates the shared
// cache rather than corrupting it: every key changes, and any entry found
// under an old key fails its seal and is treated as a miss.
//
// The secret is never used directly. Key derivation, sealing, and username
// hashing each take their own HKDF subkey, because sharing one made the
// login path a signing oracle for the seal — see derive.go and the
// security notes. An entry also carries its own expiry inside the MAC, so
// a store that ignores its TTL cannot replay an old identity: integrity
// proves who wrote a value, not when.
//
// Caching must be turned on with [WithCache] as well.
func WithSealedCacheStore(store ByteStore) Option {
	return func(c *config) error {
		if store == nil {
			return fmt.Errorf("%w: WithSealedCacheStore was given a nil store", ErrInvalidOption)
		}

		c.sealedStore = store

		return nil
	}
}

// WithCacheSecret sets the key that turns a credential into a cache key,
// so that several replicas derive the same key for the same login.
//
// Without it the secret is drawn from the system CSPRNG when the
// authenticator is built, which is what you want for a single process: the
// key is unrelated between runs and worthless outside the one that made
// it. Set this only when a cache is genuinely shared, and treat the value
// as a secret — anybody holding it can test a guessed credential against
// the cache offline.
//
// Use 32 bytes — 256 bits, the size this package generates when you do not
// supply one. Sixteen is the hard floor for compatibility, and a secret
// below 32 is logged as a warning at startup.
//
// Treat it the way you treat the service account password, and not as the
// same value: it is a different secret protecting a different thing, and
// reusing one for both means a compromise of either is a compromise of
// both. Rotate it on the same schedule, and remember that rotating it
// invalidates the shared cache rather than corrupting it — every key
// changes at once, so the worst that happens is a cold cache.
func WithCacheSecret(secret []byte) Option {
	return func(c *config) error {
		const minimum = 16

		if len(secret) < minimum {
			return fmt.Errorf(
				"%w: cache secret is %d bytes, want at least %d",
				ErrInvalidOption, len(secret), minimum,
			)
		}

		c.cacheSecret = append([]byte(nil), secret...)

		return nil
	}
}

// WithCacheUsernameHashing replaces the username the cache store sees
// with a keyed hash of it, under the same secret as the key.
//
// The key already hides the credential, but the username travels alongside
// it in the clear, because [Client.InvalidateUser] has to find an
// account's entries without knowing the password. On a store that is
// shared, remote, or backed up, that username is personal data this
// package put there. With this, the store holds nothing anybody can read,
// and invalidation still works because it hashes the same way.
//
// What it costs is the ability to look in the cache and see who is in it,
// which is a real debugging affordance — which is why this is a choice
// rather than the default.
func WithCacheUsernameHashing() Option {
	return func(c *config) error {
		c.hashCacheUsernames = true

		return nil
	}
}

// WithCacheSize bounds the number of cached entries. When the bound is
// reached the oldest entries are dropped.
func WithCacheSize(entries int) Option {
	return func(c *config) error {
		if entries < 1 {
			return fmt.Errorf("%w: cache size %d is below 1", ErrInvalidOption, entries)
		}

		c.cacheMaxEntries = entries

		return nil
	}
}

// WithLockoutProtection refuses an account locally after too many recent
// failures, so that the attempts never reach the directory's own lockout
// counter.
//
//	ldapauth.WithLockoutProtection(4, 5*time.Minute, time.Minute)
//
// The threat is not brute force. A directory that locks an account after
// five failures is a directory where anybody who knows a username can lock
// that account out from anywhere, by getting the password wrong five
// times — no access needed, and the victim is the one who calls the help
// desk. This package already refuses to make it worse by retrying a
// rejected credential; this is what stops it being the instrument.
//
// Attempts served from the cache do not count and are not blocked, so a
// user who logged in recently keeps working while somebody guesses at
// their username. Without a cache there is nothing to serve them from, and
// they are refused along with the attacker — which is a local cooldown of
// a minute rather than a directory lockout an administrator has to clear,
// but it is a real cost and it is why this is not on by default.
//
// Two limits worth knowing. It counts failures per account, not requests
// per client, so it is not a rate limiter — put one in front. And the
// counters are per process, so twenty replicas pass twenty times the
// threshold through before all of them are blocking. Making that exact
// would mean a round trip to somewhere shared on every failed login, paid
// on the attack path to make the attack slightly harder.
//
// Zero attempts turns it off, which is the default.
func WithLockoutProtection(attempts int, window, cooldown time.Duration) Option {
	return func(c *config) error {
		if attempts < 0 {
			return fmt.Errorf("%w: lockout attempts %d is negative", ErrInvalidOption, attempts)
		}

		if attempts > 0 {
			if window <= 0 {
				return fmt.Errorf("%w: lockout window %s is not positive", ErrInvalidOption, window)
			}

			if cooldown <= 0 {
				return fmt.Errorf("%w: lockout cooldown %s is not positive", ErrInvalidOption, cooldown)
			}
		}

		c.throttleAttempts = attempts
		c.throttleWindow = window
		c.throttleCooldown = cooldown

		return nil
	}
}

// ---- input handling -------------------------------------------------------

// WithUsernameMaxLength rejects usernames longer than n before any network
// call. The default is DefaultUsernameMaxLength.
func WithUsernameMaxLength(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("%w: username max length %d is below 1", ErrInvalidOption, n)
		}

		c.usernameMaxLength = n

		return nil
	}
}

// WithPasswordMaxLength rejects passwords longer than n before any network
// call. The default is DefaultPasswordMaxLength.
//
// It is not about password strength. It is about not carrying a megabyte
// from a request body to a directory, once per request, for as long as
// somebody cares to send one.
func WithPasswordMaxLength(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("%w: password max length %d is below 1", ErrInvalidOption, n)
		}

		c.passwordMaxLength = n

		return nil
	}
}

// WithCaseFoldUsername lower-cases the username before it is used as a
// cache key, so that "Alice" and "alice" share one entry on a directory
// that matches case-insensitively — which is most of them.
//
// It changes the cache key only. The username sent to the directory is
// always the one the caller supplied, because deciding how a username
// compares is the directory's job and its matching rules are not knowable
// from here.
func WithCaseFoldUsername() Option {
	return func(c *config) error {
		c.caseFoldUsername = true

		return nil
	}
}

// WithUsernameRedaction replaces the username with "[redacted]" in log
// records and in AuthError. Set it where the logs are less trusted than
// the directory — a shipped log aggregator, a support bundle.
func WithUsernameRedaction() Option {
	return func(c *config) error {
		c.redactUsername = true

		return nil
	}
}

// ---- pluggable behaviour ---------------------------------------------------

// WithPrincipalMapper replaces the mapping from a completed authentication
// to an [Identity].
//
// Use it to produce your application's own user type, or to enrich the
// [Principal] this package ships with something the directory does not
// know. The mapper runs inside the caller's context and inside the retry
// loop, so it should be quick and it must be safe to run twice.
//
// [Mapping.Entry] is the directory entry, and it is nil unless the
// configuration asked for something to be read from it. A mapper that
// wants an attribute has to say so with [WithAttributes], the same as
// anything else — the entry is not fetched speculatively, because a round
// trip nobody needs is a round trip on every login.
//
//	ldapauth.WithPrincipalMapper(ldapauth.PrincipalMapperFunc(
//	    func(m ldapauth.Mapping) (ldapauth.Identity, error) {
//	        return &user{dn: m.DN, name: m.Username, groups: m.Groups}, nil
//	    },
//	))
func WithPrincipalMapper(mapper PrincipalMapper) Option {
	return func(c *config) error {
		if mapper == nil {
			return fmt.Errorf("%w: WithPrincipalMapper was given a nil mapper", ErrInvalidOption)
		}

		c.mapper = mapper

		return nil
	}
}

// WithGroupResolver replaces group resolution entirely.
//
// The default resolves groups from the directory in whichever of the three
// ways the group options asked for. Replace it when membership lives
// somewhere the directory is not, or when your directory has a group
// scheme this package does not model. The resolver is handed a [Searcher]
// so that it can still ask the directory, on the authenticator's
// connection and with the authenticator's identity.
//
// It replaces the built-in resolution rather than adding to it: the group
// source options are not consulted, so a resolver that wants both should
// compose the directory's answer with its own.
func WithGroupResolver(resolver GroupResolver) Option {
	return func(c *config) error {
		if resolver == nil {
			return fmt.Errorf("%w: WithGroupResolver was given a nil resolver", ErrInvalidOption)
		}

		c.groupResolver = resolver

		return nil
	}
}

// ---- observability --------------------------------------------------------

// WithLogger attaches a *slog.Logger.
//
// Logging is optional and log/slog is in the standard library, so this
// costs no dependency. The package logs stages, outcomes, and errors. It
// logs the username, or "[redacted]" under WithUsernameRedaction. It never
// logs a password, a service account password, or any attribute value.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) error {
		if logger == nil {
			return fmt.Errorf("%w: WithLogger was given a nil logger", ErrInvalidOption)
		}

		c.logger = logger

		return nil
	}
}

// WithMetrics attaches a Metrics implementation. Embed NoopMetrics in it
// so that methods added to the interface later do not break your build.
func WithMetrics(m Metrics) Option {
	return func(c *config) error {
		if m == nil {
			return fmt.Errorf("%w: WithMetrics was given a nil implementation", ErrInvalidOption)
		}

		c.metrics = m

		return nil
	}
}

// WithClock replaces the package's source of time.
//
// It exists for tests: cache expiry, failover cooldowns, and connection
// lifetimes are all decided against this clock, and driving them from a
// test is otherwise a matter of sleeping and hoping. The function must be
// safe to call from several goroutines at once.
func WithClock(now func() time.Time) Option {
	return func(c *config) error {
		if now == nil {
			return fmt.Errorf("%w: WithClock was given a nil function", ErrInvalidOption)
		}

		c.now = now

		return nil
	}
}

// ensureTLS returns the TLS config to mutate, creating it with a sane
// floor on first use so that no option has to remember to set MinVersion.
func (c *config) ensureTLS() *tls.Config {
	if c.tlsConfig == nil {
		c.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	return c.tlsConfig
}

func setAttribute(option, name string, dst *string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: %s was given an empty attribute name", ErrInvalidOption, option)
	}

	*dst = name

	return nil
}
