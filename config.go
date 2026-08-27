package ldapauth

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/ctolon/ldap-authenticator/internal/backoff"
	"github.com/go-ldap/ldap/v3"
)

// Search scopes, re-exported so that configuring this package does not
// oblige you to import go-ldap as well.
const (
	// ScopeBaseObject searches the base entry only.
	ScopeBaseObject = ldap.ScopeBaseObject

	// ScopeSingleLevel searches the immediate children of the base entry.
	ScopeSingleLevel = ldap.ScopeSingleLevel

	// ScopeWholeSubtree searches the base entry and everything beneath it.
	// This is the default for both user and group searches.
	ScopeWholeSubtree = ldap.ScopeWholeSubtree
)

// The defaults every option starts from. They are exported because a
// default you cannot name is a default you cannot reason about: a
// deployment that wants "the library default, but doubled" should be able
// to write that down.
const (
	// DefaultDialTimeout bounds a single TCP connect plus TLS handshake.
	DefaultDialTimeout = 5 * time.Second

	// DefaultOperationTimeout bounds a single LDAP operation once the
	// connection is up. It exists because a server that accepts a
	// connection and then stops answering is a real failure mode, and
	// without this the only thing bounding it is the caller's context.
	DefaultOperationTimeout = 10 * time.Second

	// DefaultRequestTimeout bounds one whole call to Authenticate — dial,
	// bind, search, group resolution, and any retries — when the caller's
	// context carries no earlier deadline.
	DefaultRequestTimeout = 15 * time.Second

	// DefaultFailoverCooldown is how long a URL that failed to dial is
	// tried last rather than first.
	DefaultFailoverCooldown = 30 * time.Second

	// DefaultRetryMaxAttempts is how many *retries* a retriable failure
	// gets, over and above the first attempt.
	DefaultRetryMaxAttempts = 2

	// DefaultRetryBaseDelay is the first backoff interval.
	DefaultRetryBaseDelay = 50 * time.Millisecond

	// DefaultRetryMaxDelay caps a single backoff interval.
	DefaultRetryMaxDelay = 2 * time.Second

	// DefaultRetryMultiplier is the growth factor between retries.
	DefaultRetryMultiplier = 2.0

	// DefaultRetryMaxElapsed caps the total time spent retrying.
	DefaultRetryMaxElapsed = 10 * time.Second

	// DefaultPoolSize is the maximum number of pooled service-account
	// connections.
	DefaultPoolSize = 10

	// DefaultPoolMaxLifetime is how long a pooled connection may live
	// before it is retired, whether or not it still works. Directories
	// behind a load balancer need this: without it, connections pin
	// themselves to whichever backend was up when the process started.
	DefaultPoolMaxLifetime = 30 * time.Minute

	// DefaultPoolMaxIdleTime is how long an unused pooled connection is
	// kept before being closed.
	DefaultPoolMaxIdleTime = 5 * time.Minute

	// DefaultCacheTTL is how long a successful authentication may be
	// served from cache when caching is enabled.
	DefaultCacheTTL = 30 * time.Second

	// DefaultNegativeCacheTTL is how long a rejected authentication may be
	// served from cache. It is deliberately much shorter than the positive
	// TTL: a user who has just fixed their password should not be locked
	// out by this package's memory.
	DefaultNegativeCacheTTL = 5 * time.Second

	// MaxCacheTTL is the hard ceiling on either cache TTL. A credential
	// cache is a window during which a disabled account still works, and
	// there is no deployment for which that window should be measured in
	// hours.
	MaxCacheTTL = 5 * time.Minute

	// DefaultCacheMaxEntries bounds the cache, which is what makes it a
	// cache rather than a memory leak with good manners.
	DefaultCacheMaxEntries = 4096

	// DefaultLockoutWindow is how long failures are counted over by
	// WithLockoutProtection.
	DefaultLockoutWindow = 5 * time.Minute

	// DefaultLockoutCooldown is how long an account is refused locally
	// once the threshold is reached.
	DefaultLockoutCooldown = time.Minute

	// DefaultLockoutMaxAccounts bounds how many accounts the throttle
	// tracks. The keys come from a login form, so the bound is what stops
	// somebody inventing usernames until the process runs out of memory.
	DefaultLockoutMaxAccounts = 4096

	// DefaultUsernameMaxLength is the longest username accepted before the
	// request is rejected unread.
	DefaultUsernameMaxLength = 256

	// DefaultPasswordMaxLength is the longest password accepted before the
	// request is rejected unread. Directories store hashes of bounded
	// inputs; a megabyte arriving in a password field is not a login.
	DefaultPasswordMaxLength = 1024

	// DefaultNestedGroupDepth bounds recursive group expansion.
	DefaultNestedGroupDepth = 4

	// DefaultGroupNameAttribute is the attribute read as a group's name.
	DefaultGroupNameAttribute = "cn"

	// DefaultMemberOfAttribute is the attribute read for a user's group
	// memberships under GroupsFromMemberOf.
	DefaultMemberOfAttribute = "memberOf"
)

// GroupSource selects how a Principal's groups are discovered.
type GroupSource int

const (
	// GroupsDisabled resolves no groups. Principal.Groups is always empty
	// and no group search is issued. This is the default: group resolution
	// costs a round trip and not every application needs it.
	GroupsDisabled GroupSource = iota

	// GroupsFromMemberOf reads the memberships off the user's own entry,
	// from the attribute named by WithMemberOfAttribute. It costs no extra
	// round trip and it is what Active Directory and any OpenLDAP with the
	// memberof overlay will give you.
	GroupsFromMemberOf

	// GroupsFromSearch searches the group tree for entries that name the
	// user as a member. Use it on directories with no memberOf overlay, or
	// where group membership lives outside the user's entry.
	GroupsFromSearch
)

// String returns a stable, lower-case name for the source, suitable for
// a log field or a metrics label.
func (g GroupSource) String() string {
	switch g {
	case GroupsDisabled:
		return "disabled"
	case GroupsFromMemberOf:
		return "member-of"
	case GroupsFromSearch:
		return "search"
	default:
		return fmt.Sprintf("GroupSource(%d)", int(g))
	}
}

func (g GroupSource) valid() bool { return g >= GroupsDisabled && g <= GroupsFromSearch }

// config is the resolved, validated configuration. Options write to it,
// New validates it, and nothing mutates it afterwards — the Authenticator
// holds it by value and every goroutine reads the same frozen copy, which
// is why no lock guards it.
type config struct {
	urls []string

	dialer Dialer

	tlsConfig *tls.Config

	startTLS bool

	insecureNoTLS bool

	failoverPolicy FailoverPolicy

	failoverCooldown time.Duration

	dialTimeout time.Duration

	operationTimeout time.Duration

	requestTimeout time.Duration

	// bindDN is the direct-bind template. Exactly one of bindDN and
	// userFilter is set; New rejects both and neither.
	bindDN template

	// serviceDN and servicePassword authenticate the pooled connections
	// used for searching. They are empty for a direct bind that does no
	// lookup, and for a directory that permits anonymous search.
	serviceDN string

	servicePassword string

	// anonymousService allows searching without binding at all. It has to
	// be asked for explicitly, because a directory that answers anonymous
	// searches and a directory that is misconfigured look identical from
	// here.
	anonymousService bool

	// passwordPolicyControl asks for the RFC-draft password policy
	// control on binds, which is how a directory other than Active
	// Directory says why it refused.
	passwordPolicyControl bool

	referralPolicy ReferralPolicy

	userBaseDN string

	userFilter template

	userScope int

	userDerefAliases int

	userSizeLimit int

	// pagingSize, when non-zero, turns user and group searches into paged
	// searches. Active Directory caps a search at 1000 entries by default
	// and simply truncates past it; a group search over a large directory
	// needs paging to see the whole answer.
	pagingSize uint32

	usernameAttribute string

	displayNameAttribute string

	emailAttribute string

	extraAttributes []string

	groupSource GroupSource

	groupBaseDN string

	groupFilter template

	groupScope int

	groupNameAttribute string

	memberOfAttribute string

	// nestedGroups walks group-of-group membership. Under
	// GroupsFromMemberOf it issues one lookup per group; under
	// GroupsFromSearch it re-runs the group filter with each group's DN.
	nestedGroups bool

	// activeDirectoryChain records that the group filter carries the
	// LDAP_MATCHING_RULE_IN_CHAIN matching rule, so the server has already
	// done the transitive closure and this package must not walk the
	// membership graph a second time.
	activeDirectoryChain bool

	nestedGroupDepth int

	// groupsAsDN reports group DNs rather than group names.
	groupsAsDN bool

	poolSize int

	poolMinIdle int

	poolMaxLifetime time.Duration

	poolMaxIdleTime time.Duration

	poolHealthCheck bool

	cacheEnabled bool

	// hashCacheUsernames sends the store a keyed hash of the username
	// instead of the username, so that a shared store holds no personal
	// data at all.
	hashCacheUsernames bool

	// throttle* configure the local lockout protection. attempts of zero
	// leaves it off.
	throttleAttempts int

	throttleWindow time.Duration

	throttleCooldown time.Duration

	// cacheStore replaces the in-memory cache; see WithCacheStore.
	cacheStore Cache

	// cacheSecret keys the credential hash. Empty means "generate a
	// per-process one", which is the default and the safe answer for a
	// single process.
	cacheSecret []byte

	cacheTTL time.Duration

	cacheNegativeTTL time.Duration

	cacheMaxEntries int

	usernameMaxLength int

	passwordMaxLength int

	caseFoldUsername bool

	redactUsername bool

	logger *slog.Logger

	metrics Metrics

	// mapper and groupResolver are nil unless the caller replaced them,
	// in which case New substitutes the package's own.
	mapper PrincipalMapper

	groupResolver GroupResolver

	backoff backoff.Policy

	retryMaxAttempts int

	retryMaxElapsed time.Duration

	now func() time.Time
}

func defaultConfig() *config {
	return &config{
		failoverPolicy:     FailoverInOrder,
		failoverCooldown:   DefaultFailoverCooldown,
		dialTimeout:        DefaultDialTimeout,
		operationTimeout:   DefaultOperationTimeout,
		requestTimeout:     DefaultRequestTimeout,
		userScope:          ScopeWholeSubtree,
		userDerefAliases:   ldap.NeverDerefAliases,
		usernameAttribute:  "",
		groupSource:        GroupsDisabled,
		groupScope:         ScopeWholeSubtree,
		groupNameAttribute: DefaultGroupNameAttribute,
		memberOfAttribute:  DefaultMemberOfAttribute,
		nestedGroupDepth:   DefaultNestedGroupDepth,
		poolSize:           DefaultPoolSize,
		poolMaxLifetime:    DefaultPoolMaxLifetime,
		poolMaxIdleTime:    DefaultPoolMaxIdleTime,
		poolHealthCheck:    true,
		cacheTTL:           DefaultCacheTTL,
		cacheNegativeTTL:   DefaultNegativeCacheTTL,
		cacheMaxEntries:    DefaultCacheMaxEntries,
		usernameMaxLength:  DefaultUsernameMaxLength,
		passwordMaxLength:  DefaultPasswordMaxLength,
		logger:             discardLogger,
		metrics:            NoopMetrics{},
		retryMaxAttempts:   DefaultRetryMaxAttempts,
		retryMaxElapsed:    DefaultRetryMaxElapsed,
		backoff: backoff.Policy{
			Base:       DefaultRetryBaseDelay,
			Max:        DefaultRetryMaxDelay,
			Multiplier: DefaultRetryMultiplier,
		},
		now: time.Now,
	}
}

// searchTimeLimit is the server-side time limit, in seconds, derived from
// the operation timeout. Rounding up by a second keeps the server's own
// limit from firing just before the client's and turning a clean timeout
// into a race.
func (c *config) searchTimeLimit() int {
	if c.operationTimeout <= 0 {
		return 0
	}

	return int(c.operationTimeout.Seconds()) + 1
}

// searchesDirectory reports whether the configuration ever needs a
// connection that is not the user's own — for the user search, for a
// group search, or for an attribute lookup after a direct bind. When it
// does not, the pool is never built.
func (c *config) searchesDirectory() bool {
	switch {
	case !c.userFilter.isZero():
		return true
	case c.groupSource != GroupsDisabled:
		return true

	// A replaced group resolver is handed a Searcher, and there is no way
	// to know from here whether it will use it. Build the pool if a
	// service account was configured: the cost of an unused pool is a
	// little memory, and the cost of not building one is that the
	// resolver silently searches with the user's own permissions.
	case c.groupResolver != nil:
		return true

	default:
		return c.userBaseDN != "" && len(c.attributeList()) > 0
	}
}

// directBind reports which strategy is configured.
func (c *config) directBind() bool { return !c.bindDN.isZero() }

// attributeList is the set of attributes a user search asks for. An empty
// result means "ask for none", which is a real request: it makes the
// search cheaper when the caller only wants to know that the password was
// right.
func (c *config) attributeList() []string {
	seen := make(map[string]struct{}, 8)
	out := make([]string, 0, 8)

	add := func(name string) {
		if name == "" {
			return
		}

		if _, dup := seen[name]; dup {
			return
		}

		seen[name] = struct{}{}
		out = append(out, name)
	}

	add(c.usernameAttribute)
	add(c.displayNameAttribute)
	add(c.emailAttribute)

	if c.groupSource == GroupsFromMemberOf {
		add(c.memberOfAttribute)
	}

	for _, name := range c.extraAttributes {
		add(name)
	}

	return out
}

// validate is the whole of New's checking. Every failure it reports wraps
// ErrInvalidOption and names the option that is wrong, because the person
// reading this error is holding a configuration file, not a debugger.
func (c *config) validate() error {
	if len(c.urls) == 0 {
		return fmt.Errorf("%w: no server URL configured; use WithURL or WithURLs", ErrInvalidOption)
	}

	for _, u := range c.urls {
		if err := validateURL(u); err != nil {
			return err
		}
	}

	if err := c.validateTLS(); err != nil {
		return err
	}

	if err := c.validateStrategy(); err != nil {
		return err
	}

	if err := c.validateGroups(); err != nil {
		return err
	}

	return c.validateLimits()
}

func (c *config) validateTLS() error {
	if c.insecureNoTLS || c.startTLS {
		return nil
	}

	for _, u := range c.urls {
		if isPlaintextURL(u) {
			return fmt.Errorf(
				"%w: URL %q is plaintext and neither StartTLS nor WithInsecureNoTLS was configured. "+
					"A simple bind over plaintext puts the password on the wire in the clear",
				ErrTLSRequired, u,
			)
		}
	}

	return nil
}

func (c *config) validateStrategy() error {
	switch {
	case c.directBind() && !c.userFilter.isZero():
		return fmt.Errorf(
			"%w: both WithDirectBind and WithUserFilter are set; a deployment binds one way or the other",
			ErrInvalidOption,
		)

	case !c.directBind() && c.userFilter.isZero():
		return fmt.Errorf(
			"%w: no bind strategy configured; use WithDirectBind for a DN template, "+
				"or WithUserSearch for a service-account search",
			ErrInvalidOption,
		)
	}

	if c.directBind() && !c.bindDN.requires(placeholderUsername) {
		return fmt.Errorf(
			"%w: direct bind template %q does not use {{username}}, so every login would bind as the same DN",
			ErrInvalidOption, c.bindDN,
		)
	}

	if !c.userFilter.isZero() {
		if c.userBaseDN == "" {
			return fmt.Errorf("%w: WithUserSearch needs a base DN to search under", ErrInvalidOption)
		}

		if c.serviceDN == "" && !c.anonymousService {
			return fmt.Errorf(
				"%w: WithUserSearch needs service-account credentials; "+
					"use WithServiceAccount, or WithAnonymousServiceBind if the directory really does allow it",
				ErrInvalidOption,
			)
		}

		if c.serviceDN != "" && c.servicePassword == "" {
			return fmt.Errorf(
				"%w: service account %q has an empty password, which LDAP would treat as an anonymous bind",
				ErrInvalidOption, c.serviceDN,
			)
		}
	}

	if c.serviceDN != "" && c.anonymousService {
		return fmt.Errorf(
			"%w: WithServiceAccount and WithAnonymousServiceBind are mutually exclusive",
			ErrInvalidOption,
		)
	}

	if !scopeValid(c.userScope) {
		return fmt.Errorf("%w: user search scope %d is not a valid LDAP scope", ErrInvalidOption, c.userScope)
	}

	if !c.referralPolicy.valid() {
		return fmt.Errorf("%w: referral policy %d is not valid", ErrInvalidOption, int(c.referralPolicy))
	}

	return nil
}

func (c *config) validateGroups() error {
	if !c.groupSource.valid() {
		return fmt.Errorf("%w: group source %d is not valid", ErrInvalidOption, int(c.groupSource))
	}

	if c.groupSource == GroupsFromSearch {
		if c.groupBaseDN == "" {
			return fmt.Errorf("%w: WithGroupSearch needs a base DN to search under", ErrInvalidOption)
		}

		if c.groupFilter.isZero() {
			return fmt.Errorf("%w: WithGroupSearch needs a filter template", ErrInvalidOption)
		}

		if !scopeValid(c.groupScope) {
			return fmt.Errorf("%w: group search scope %d is not a valid LDAP scope", ErrInvalidOption, c.groupScope)
		}
	}

	if c.groupSource == GroupsDisabled && !c.groupFilter.isZero() {
		return fmt.Errorf(
			"%w: a group filter is configured but the group source is disabled; "+
				"WithGroupSearch sets both",
			ErrInvalidOption,
		)
	}

	if c.activeDirectoryChain && c.groupSource != GroupsFromSearch {
		return fmt.Errorf(
			"%w: the Active Directory matching rule is a group search; "+
				"a later WithMemberOfGroups undid WithActiveDirectoryGroups",
			ErrInvalidOption,
		)
	}

	if c.nestedGroupDepth < 1 {
		return fmt.Errorf("%w: nested group depth %d is below 1", ErrInvalidOption, c.nestedGroupDepth)
	}

	return nil
}

func (c *config) validateLimits() error {
	durations := []struct {
		name  string
		value time.Duration
	}{
		{"dial timeout", c.dialTimeout},
		{"operation timeout", c.operationTimeout},
		{"request timeout", c.requestTimeout},
		{"failover cooldown", c.failoverCooldown},
		{"pool max lifetime", c.poolMaxLifetime},
		{"pool max idle time", c.poolMaxIdleTime},
		{"retry max elapsed", c.retryMaxElapsed},
	}

	for _, d := range durations {
		if d.value < 0 {
			return fmt.Errorf("%w: %s %s is negative", ErrInvalidOption, d.name, d.value)
		}
	}

	if c.dialTimeout == 0 {
		return fmt.Errorf("%w: dial timeout of zero would never connect", ErrInvalidOption)
	}

	if c.poolSize < 1 {
		return fmt.Errorf("%w: pool size %d is below 1", ErrInvalidOption, c.poolSize)
	}

	if c.poolMinIdle > c.poolSize {
		return fmt.Errorf(
			"%w: pool minimum idle %d exceeds pool size %d",
			ErrInvalidOption, c.poolMinIdle, c.poolSize,
		)
	}

	if c.usernameMaxLength < 1 {
		return fmt.Errorf("%w: username max length %d is below 1", ErrInvalidOption, c.usernameMaxLength)
	}

	if c.passwordMaxLength < 1 {
		return fmt.Errorf("%w: password max length %d is below 1", ErrInvalidOption, c.passwordMaxLength)
	}

	if c.retryMaxAttempts < 0 {
		return fmt.Errorf("%w: retry max attempts %d is negative", ErrInvalidOption, c.retryMaxAttempts)
	}

	if !c.cacheEnabled && (c.cacheStore != nil || len(c.cacheSecret) > 0) {
		return fmt.Errorf(
			"%w: a cache store or secret is configured but caching is off; WithCache turns it on",
			ErrInvalidOption,
		)
	}

	if c.throttleAttempts < 0 {
		return fmt.Errorf("%w: lockout attempts %d is negative", ErrInvalidOption, c.throttleAttempts)
	}

	if c.throttleAttempts > 0 {
		if c.throttleWindow <= 0 {
			return fmt.Errorf("%w: lockout window %s is not positive", ErrInvalidOption, c.throttleWindow)
		}

		if c.throttleCooldown <= 0 {
			return fmt.Errorf("%w: lockout cooldown %s is not positive", ErrInvalidOption, c.throttleCooldown)
		}
	}

	if c.hashCacheUsernames && !c.cacheEnabled {
		return fmt.Errorf(
			"%w: cache username hashing is configured but caching is off; WithCache turns it on",
			ErrInvalidOption,
		)
	}

	if c.cacheEnabled {
		if c.cacheTTL <= 0 {
			return fmt.Errorf("%w: cache TTL %s is not positive", ErrInvalidOption, c.cacheTTL)
		}

		if c.cacheTTL > MaxCacheTTL || c.cacheNegativeTTL > MaxCacheTTL {
			return fmt.Errorf(
				"%w: cache TTL exceeds the %s ceiling; a longer window is a disabled account that still works",
				ErrInvalidOption, MaxCacheTTL,
			)
		}

		if c.cacheMaxEntries < 1 {
			return fmt.Errorf("%w: cache max entries %d is below 1", ErrInvalidOption, c.cacheMaxEntries)
		}
	}

	return nil
}

// scopeValid and derefValid ask go-ldap which values it knows, rather than
// listing them again here. A value the client cannot name is a value the
// server will not be sent.
func scopeValid(scope int) bool {
	_, ok := ldap.ScopeMap[scope]

	return ok
}

func derefValid(deref int) bool {
	_, ok := ldap.DerefMap[deref]

	return ok
}
