package ldapauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// An Authenticator verifies credentials against a directory.
//
// [New] returns a [*Client], which is the implementation this package
// ships. This interface exists so that the things built on top of an
// authenticator — the middleware in httpauth, the framework adapters under
// contrib, and your own handlers — depend on the behaviour rather than on
// the type. A test can substitute a fake, and a deployment can wrap the
// real one in a decorator that adds a circuit breaker, a second directory,
// or a local account for the break-glass user, without any of them
// knowing.
//
// Every method is safe for concurrent use.
type Authenticator interface {
	// Authenticate verifies a username and password.
	Authenticate(ctx context.Context, username, password string) (Identity, error)

	// Lookup reads an identity without verifying a password.
	Lookup(ctx context.Context, username string) (Identity, error)

	// HealthCheck reports whether the directory is reachable.
	HealthCheck(ctx context.Context) error

	// Stats reports current occupancy.
	Stats(ctx context.Context) Stats

	// InvalidateUser drops an account's cached outcomes.
	InvalidateUser(ctx context.Context, username string) (int, error)

	// InvalidateAll empties the cache.
	InvalidateAll(ctx context.Context) (int, error)

	// Close releases the pooled connections.
	Close() error
}

// Client is the [Authenticator] this package implements.
//
// Build one per directory at startup and share it: it is safe for
// concurrent use, it owns the connection pool, and constructing one
// validates the whole configuration. Close it when the process is done
// with it.
type Client struct {
	cfg *config

	dialer Dialer

	servers *serverSet

	// pool holds service-account connections. It is nil when the
	// configuration never searches — a direct bind with no attributes and
	// no groups needs no second identity.
	pool *pool

	// cache is nil unless WithCache or WithCacheStore was given.
	cache Cache

	// cacheSecret keys the HMAC that turns a credential into a cache key,
	// so that no Cache implementation ever sees one.
	cacheSecret []byte

	// flights collapses concurrent authentications of the same credential.
	// It is nil when there is no cache, because without one every request
	// is meant to reach the directory.
	flights *inflight

	// throttle is nil unless WithLockoutProtection was given.
	throttle *throttle

	mapper PrincipalMapper

	groups GroupResolver

	// closed is closed by Close, and is what every bounded wait selects on
	// so that shutting down does not have to wait out a backoff.
	closed chan struct{}

	// shutdown cancels the contexts of work the authenticator started on
	// its own behalf, such as warming the pool.
	shutdown context.CancelFunc

	closeOnce sync.Once
}

// Client implements Authenticator. The assertion is here rather than in a
// test so that it is checked by every build, including a consumer's.
var _ Authenticator = (*Client)(nil)

// New builds a Client from the given options.
//
// It validates everything it can before returning: the URLs parse, the
// templates have the placeholders they need, the strategy is one of the
// two and not both, the numbers are in range, and TLS is either configured
// or explicitly declined. It does not talk to the directory — a directory
// that is briefly down should not stop a process from starting. Use
// [Client.HealthCheck] for that.
//
// The minimum useful configuration is a URL and a strategy:
//
//	auth, err := ldapauth.New(
//	    ldapauth.WithURL("ldaps://dc1.corp.example:636"),
//	    ldapauth.WithDirectBind("uid={{username}},ou=people,dc=corp,dc=example"),
//	)
func New(opts ...Option) (*Client, error) {
	cfg := defaultConfig()

	for i, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: option %d is nil", ErrInvalidOption, i)
		}

		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	a := &Client{
		cfg:      cfg,
		dialer:   cfg.dialer,
		servers:  newServerSet(cfg.urls, cfg.failoverPolicy, cfg.failoverCooldown, cfg.now),
		closed:   make(chan struct{}),
		shutdown: cancel,
	}

	if a.dialer == nil {
		a.dialer = &netDialer{
			tlsConfig:   defaultTLSConfig(cfg),
			startTLS:    cfg.startTLS,
			dialTimeout: cfg.dialTimeout,
			opTimeout:   cfg.operationTimeout,
		}
	}

	if cfg.searchesDirectory() && (cfg.serviceDN != "" || cfg.anonymousService) {
		a.pool = newPool(ctx, cfg, a.dialer, a.servers)

		if cfg.poolMinIdle > 0 {
			// Warming happens in the background, and its failures are the
			// pool's own business. A directory that is not up yet is a
			// reason for the first login to fail, not for the process to.
			go a.pool.warm(ctx)
		}
	}

	if err := a.initCache(cfg); err != nil {
		cancel()

		return nil, err
	}

	if cfg.throttleAttempts > 0 {
		a.throttle = newThrottle(
			cfg.throttleAttempts,
			cfg.throttleWindow,
			cfg.throttleCooldown,
			DefaultLockoutMaxAccounts,
			cfg.now,
		)
	}

	a.mapper = cfg.mapper
	if a.mapper == nil {
		a.mapper = defaultMapper{cfg: cfg}
	}

	a.groups = cfg.groupResolver
	if a.groups == nil {
		a.groups = &directoryGroups{cfg: cfg}
	}

	if len(cfg.cacheSecret) > 0 && len(cfg.cacheSecret) < recommendedCacheSecret {
		a.warn("the cache secret is shorter than recommended",
			"bytes", len(cfg.cacheSecret),
			"recommended", recommendedCacheSecret,
		)
	}

	a.info("ldap authenticator ready",
		"servers", len(cfg.urls),
		"strategy", strategyName(cfg),
		"groups", cfg.groupSource.String(),
		"pooled", a.pool != nil,
		"cached", a.cache != nil,
	)

	return a, nil
}

func (a *Client) initCache(cfg *config) error {
	if !cfg.cacheEnabled {
		return nil
	}

	a.cache = cfg.cacheStore
	if a.cache == nil {
		a.cache = NewMemoryCache(cfg.cacheMaxEntries, cfg.now)
	}

	secret := cfg.cacheSecret
	if len(secret) == 0 {
		// A per-process secret is the safe default: two runs of the same
		// program produce unrelated keys for the same credential, and a
		// key that escapes is worthless the moment the process restarts.
		// It also means replicas cannot share a cache, which is what
		// WithCacheSecret is for.
		generated, err := randomSecret()
		if err != nil {
			return fmt.Errorf("ldapauth: generating a cache secret: %w", err)
		}

		secret = generated
	}

	a.cacheSecret = secret
	a.flights = newInflight()

	return nil
}

// recommendedCacheSecret is 256 bits. Anything shorter still works; it is
// worth saying so out loud, because the secret is what stands between a
// stolen cache and offline credential testing.
const recommendedCacheSecret = 32

func defaultTLSConfig(cfg *config) *tls.Config {
	if cfg.tlsConfig != nil {
		return cfg.tlsConfig
	}

	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func strategyName(cfg *config) string {
	if cfg.directBind() {
		return "direct-bind"
	}

	return "search-then-bind"
}

// Authenticate verifies a username and password against the directory and
// returns who the directory says that is.
//
// The returned error is ErrInvalidCredentials for both a wrong password
// and an unknown user — the two are indistinguishable to the caller on
// purpose, so that a login form built on this package cannot become an
// account enumeration oracle by forgetting to collapse them. Everything
// else, from a broken connection to a malformed configuration, arrives as
// a different error, so
//
//	if errors.Is(err, ldapauth.ErrInvalidCredentials) { ... 401 ... }
//	if err != nil { ... 503 ... }
//
// is the whole of the branching a caller needs.
//
// The context bounds the entire call, retries included. When it carries no
// deadline, WithRequestTimeout supplies one.
//
// It is safe to call from many goroutines at once.
func (a *Client) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	started := a.cfg.now()

	identity, err := a.authenticate(ctx, username, password)

	a.cfg.metrics.AuthAttempt(resultLabel(err), a.cfg.now().Sub(started))

	if err != nil {
		return nil, err
	}

	return identity, nil
}

func (a *Client) authenticate(ctx context.Context, username, password string) (Identity, error) {
	if err := a.alive(); err != nil {
		return nil, err
	}

	if err := a.cfg.checkCredentials(username, password); err != nil {
		return nil, err
	}

	ctx, cancel := a.withTimeout(ctx)
	defer cancel()

	if a.cache == nil {
		if err := a.checkThrottle(username); err != nil {
			return nil, err
		}

		identity, err := a.attempt(ctx, username, password)

		a.recordAttempt(username, err)

		return identity, err
	}

	key := a.cacheKey(username, password)

	// The cache is consulted before the throttle, on purpose. A user who
	// authenticated a minute ago should not be locked out of their own
	// session because somebody else spent that minute guessing at their
	// username — and the cached answer costs the directory nothing, which
	// is what the throttle is protecting.
	if identity, hit := a.fromCache(ctx, key); hit {
		if identity == nil {
			return nil, &AuthError{
				Op:       "cache",
				Username: a.cfg.safeUsername(username),
				Err:      ErrInvalidCredentials,
			}
		}

		return identity, nil
	}

	if err := a.checkThrottle(username); err != nil {
		return nil, err
	}

	// Everything that reaches the directory goes through here, so that a
	// burst of identical logins costs one bind rather than one each.
	//
	// The work runs under a context detached from this caller's
	// cancellation but carrying its deadline. Otherwise the first caller
	// to close their browser would cancel the authentication that a
	// hundred others are waiting on, and the stampede this exists to
	// prevent would arrive anyway, one timeout later.
	work := context.WithoutCancel(ctx)

	if deadline, ok := ctx.Deadline(); ok {
		var cancelWork context.CancelFunc

		work, cancelWork = context.WithDeadline(work, deadline)
		defer cancelWork()
	}

	identity, shared, err := a.flights.do(ctx, key, func() (Identity, error) {
		identity, err := a.attempt(work, username, password)

		a.remember(work, key, username, identity, err)
		a.recordAttempt(username, err)

		return identity, err
	})

	if shared {
		a.cfg.metrics.CacheEvent(CacheCoalesced)
	}

	if err != nil {
		return nil, err
	}

	return identity, nil
}

// attempt is one authentication, retries included, with no caching around
// it.
func (a *Client) attempt(ctx context.Context, username, password string) (Identity, error) {
	var identity Identity

	err := a.withRetry(ctx, "authenticate", func(ctx context.Context) error {
		result, err := a.once(ctx, username, password)
		if err != nil {
			return err
		}

		identity = result

		return nil
	})
	if err != nil {
		a.debug("authentication failed", "username", a.cfg.safeUsername(username), "error", err)

		return nil, err
	}

	a.debug("authentication succeeded",
		"username", a.cfg.safeUsername(username),
		"dn", identity.GetDN(),
		"groups", len(identity.GetGroups()),
	)

	return identity, nil
}

// once is a single attempt: bind, read, resolve groups, map. Everything
// that wraps it — validation, caching, coalescing, retry, metrics — lives
// above.
func (a *Client) once(ctx context.Context, username, password string) (Identity, error) {
	var (
		r   *resolved
		err error
	)

	if a.cfg.directBind() {
		r, err = a.directBind(ctx, username, password)
	} else {
		r, err = a.searchThenBind(ctx, username, password)
	}

	if err != nil {
		return nil, err
	}

	defer r.close()

	return a.finish(ctx, username, r)
}

// finish turns a completed bind into an Identity: groups, then mapping.
func (a *Client) finish(ctx context.Context, username string, r *resolved) (Identity, error) {
	groups, err := a.groups.ResolveGroups(ctx, GroupRequest{
		Username: username,
		DN:       r.dn,
		Entry:    r.entry,
		Search:   a.searcherFor(r),
	})
	if err != nil {
		return nil, err
	}

	identity, err := a.mapper.MapPrincipal(Mapping{
		Username: username,
		DN:       r.dn,
		Entry:    r.entry,
		Groups:   groups,
	})
	if err != nil {
		return nil, fmt.Errorf("ldapauth: mapping the principal: %w", err)
	}

	if identity == nil {
		return nil, fmt.Errorf("%w: the principal mapper returned no identity", ErrInvalidOption)
	}

	return identity, nil
}

// Lookup reads a user's entry and groups without verifying a password.
//
// It is for the case where authentication happened elsewhere — a SAML
// assertion, a signed token, an upstream proxy — and the directory is
// still where the identity's attributes and groups live. It needs a
// service account, because there is no user bind to borrow a connection
// from.
//
// Unlike Authenticate, Lookup distinguishes a missing user: it returns
// ErrUserNotFound. There is no oracle to protect here, since the caller
// already knows who they are asking about.
func (a *Client) Lookup(ctx context.Context, username string) (Identity, error) {
	if err := a.alive(); err != nil {
		return nil, err
	}

	if err := a.cfg.checkUsername(username); err != nil {
		return nil, err
	}

	if a.pool == nil {
		return nil, fmt.Errorf(
			"%w: Lookup needs a service account; configure WithServiceAccount, "+
				"and attributes or groups for it to read",
			ErrInvalidOption,
		)
	}

	ctx, cancel := a.withTimeout(ctx)
	defer cancel()

	var identity Identity

	err := a.withRetry(ctx, "lookup", func(ctx context.Context) error {
		r, err := a.lookupOnce(ctx, username)
		if err != nil {
			return err
		}

		defer r.close()

		identity, err = a.finish(ctx, username, r)

		return err
	})
	if err != nil {
		return nil, err
	}

	return identity, nil
}

func (a *Client) lookupOnce(ctx context.Context, username string) (*resolved, error) {
	if a.cfg.directBind() {
		dn := a.cfg.bindDN.expand(escapeDNValue, map[string]string{placeholderUsername: username})

		entry, err := a.withPooledConn(ctx, func(conn Conn) (*ldap.Entry, error) {
			return a.readEntry(ctx, conn, dn)
		})
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				return nil, fmt.Errorf("%w: %s", ErrUserNotFound, a.cfg.safeUsername(username))
			}

			return nil, err
		}

		if entry == nil {
			return nil, fmt.Errorf("%w: %s", ErrUserNotFound, a.cfg.safeUsername(username))
		}

		return &resolved{dn: dn, entry: entry}, nil
	}

	entry, err := a.withPooledConn(ctx, func(conn Conn) (*ldap.Entry, error) {
		return a.searchUser(ctx, conn, username)
	})
	if err != nil {
		// searchUser reports a missing user as invalid credentials, which
		// is right for a login and wrong here: the caller of Lookup has
		// already been authenticated somewhere else and is asking a
		// question about somebody, not trying to become them.
		if errors.Is(err, ErrInvalidCredentials) {
			return nil, fmt.Errorf("%w: %s", ErrUserNotFound, a.cfg.safeUsername(username))
		}

		return nil, err
	}

	return &resolved{dn: entry.DN, entry: entry}, nil
}

// HealthCheck opens a connection, binds as the service account when one is
// configured, and issues a Who Am I. It reports what a login would hit
// without needing a real credential to hit it with.
//
// Wire it to a readiness probe, not a liveness probe: a directory that is
// down is a reason to stop taking traffic, not a reason to restart.
func (a *Client) HealthCheck(ctx context.Context) error {
	if err := a.alive(); err != nil {
		return err
	}

	ctx, cancel := a.withTimeout(ctx)
	defer cancel()

	if a.pool != nil {
		conn, err := a.pool.acquire(ctx)
		if err != nil {
			return err
		}

		err = a.operate(ctx, conn, func() error {
			_, werr := conn.WhoAmI(nil)

			return werr
		})

		a.pool.release(conn, err)

		if err != nil {
			return fmt.Errorf("ldapauth: health check: %w", err)
		}

		return nil
	}

	conn, url, err := a.servers.dial(ctx, a.dialer)
	if err != nil {
		return fmt.Errorf("ldapauth: health check: %w", err)
	}

	defer func() {
		_ = conn.Close()
		a.cfg.metrics.ConnClosed("health check")
	}()

	a.cfg.metrics.ConnOpened(url)

	// An anonymous Who Am I is refused by plenty of directories, and that
	// refusal still proves the thing worth proving: the server is up,
	// reachable, and speaking LDAP. Only a transport failure counts.
	err = a.operate(ctx, conn, func() error {
		_, werr := conn.WhoAmI(nil)

		return werr
	})
	if err != nil && resultCode(err) == 0 {
		return fmt.Errorf("ldapauth: health check on %s: %w", url, err)
	}

	return nil
}

// InvalidateUser drops every cached entry for one account and reports how
// many it dropped. Call it after changing somebody's password or their
// group memberships, rather than waiting out the TTL. It is a no-op when
// caching is off.
func (a *Client) InvalidateUser(ctx context.Context, username string) (int, error) {
	if err := a.alive(); err != nil {
		return 0, err
	}

	if a.cache == nil {
		return 0, nil
	}

	return a.cache.InvalidateUser(ctx, a.storedUsername(username))
}

// InvalidateAll empties the cache and reports how many entries it dropped.
func (a *Client) InvalidateAll(ctx context.Context) (int, error) {
	if err := a.alive(); err != nil {
		return 0, err
	}

	if a.cache == nil {
		return 0, nil
	}

	return a.cache.InvalidateAll(ctx)
}

// Stats reports the authenticator's current occupancy. It is a snapshot
// for a metrics scrape or a debug endpoint; nothing in the package
// branches on it.
//
// The context is there for the cache, which may live somewhere else. A
// cache that cannot answer leaves CacheEntries at -1 rather than failing
// the call: a debug endpoint should not go down because Redis did.
//
// Stats is the one method that still answers after Close. It reports the
// last state rather than an error, because the caller is a metrics scrape
// or a debug handler and neither of them has anything useful to do with
// ErrClosed while the process is on its way out.
func (a *Client) Stats(ctx context.Context) Stats {
	s := Stats{
		Servers:        len(a.cfg.urls),
		HealthyServers: a.servers.healthy(),
	}

	if a.pool != nil {
		s.PoolInUse, s.PoolIdle = a.pool.stats()
		s.PoolSize = a.cfg.poolSize
	}

	if a.throttle != nil {
		s.BlockedAccounts = a.throttle.blocked()
	}

	if a.cache == nil {
		return s
	}

	entries, err := a.cache.Len(ctx)
	if err != nil {
		a.debug("cache could not report its size", "error", err)

		s.CacheEntries = -1

		return s
	}

	s.CacheEntries = entries

	return s
}

// Close releases the pooled connections. Calls already in flight are not
// interrupted; they finish against connections that are closed on release.
//
// Close is idempotent, and every method afterwards returns ErrClosed —
// except Stats, which reports the last state, because a metrics scrape has
// nothing useful to do with an error while the process is shutting down.
//
// The cache is deliberately not emptied. A shared one belongs to whoever
// owns it, and one replica's shutdown has no business throwing away
// another's entries.
func (a *Client) Close() error {
	var err error

	a.closeOnce.Do(func() {
		close(a.closed)
		a.shutdown()

		if a.pool != nil {
			err = a.pool.close()
		}

		// The cache is deliberately left alone. A shared one belongs to
		// whoever owns it, and emptying it here would let one replica's
		// shutdown throw away every other replica's entries — and block
		// the shutdown on a round trip to do it. A local one is about to
		// be garbage anyway.

		a.info("ldap authenticator closed")
	})

	return err
}

func (a *Client) alive() error {
	select {
	case <-a.closed:
		return ErrClosed
	default:
		return nil
	}
}

// withTimeout applies the configured request timeout, unless the caller's
// context already has an earlier deadline. The caller's deadline always
// wins when it is tighter, because it is the one that knows what the
// request is for.
func (a *Client) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if a.cfg.requestTimeout <= 0 {
		return context.WithCancel(ctx)
	}

	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= a.cfg.requestTimeout {
		return context.WithCancel(ctx)
	}

	return context.WithTimeout(ctx, a.cfg.requestTimeout)
}

// cacheKey turns a credential into an opaque key.
//
// The username is included in the hashed input as well as being stored
// alongside it, so that two accounts which happen to share a password do
// not share an entry.
func (a *Client) cacheKey(username, password string) string {
	mac := hmac.New(sha256.New, a.cacheSecret)
	mac.Write([]byte(a.cacheName(username)))
	mac.Write([]byte{0})
	mac.Write([]byte(password))

	return string(mac.Sum(nil))
}

// checkThrottle refuses an account this process has seen fail too often
// too recently, without asking the directory.
func (a *Client) checkThrottle(username string) error {
	if a.throttle == nil {
		return nil
	}

	if ok, retryAfter := a.throttle.allow(username); !ok {
		a.warn("refusing locally to protect the directory's lockout policy",
			"username", a.cfg.safeUsername(username),
			"retry_after", retryAfter,
		)

		return &AuthError{
			Op:       "throttle",
			Username: a.cfg.safeUsername(username),
			Err:      fmt.Errorf("%w: try again in %s", ErrTooManyAttempts, retryAfter.Round(time.Second)),
		}
	}

	return nil
}

// recordAttempt tells the throttle how an attempt that reached the
// directory turned out.
//
// Only a refused credential counts. A directory that was unreachable says
// nothing about whether the password was right, and counting it would mean
// an outage locking out every account that tried to log in during it.
func (a *Client) recordAttempt(username string, err error) {
	if a.throttle == nil {
		return
	}

	switch {
	case err == nil:
		a.throttle.succeed(username)
	case errors.Is(err, ErrInvalidCredentials):
		a.throttle.fail(username)
	}
}

func (a *Client) fromCache(ctx context.Context, key string) (Identity, bool) {
	identity, hit, err := a.cache.Get(ctx, key)
	if err != nil {
		// A cache that is down must not be a directory that is down.
		a.warn("cache lookup failed; falling through to the directory", "error", err)
		a.cfg.metrics.CacheEvent(CacheError)

		return nil, false
	}

	if !hit {
		a.cfg.metrics.CacheEvent(CacheMiss)

		return nil, false
	}

	if identity == nil {
		a.cfg.metrics.CacheEvent(CacheNegativeHit)

		return nil, true
	}

	a.cfg.metrics.CacheEvent(CacheHit)

	return identity, true
}

// remember stores an outcome. Only the two outcomes that are about this
// credential are cached: a success, and a rejection. A connection failure
// says nothing about whether the password is right, and caching it would
// serve an outage back to the caller for the length of the TTL.
func (a *Client) remember(ctx context.Context, key, username string, identity Identity, err error) {
	var cerr error

	switch {
	case err == nil:
		cerr = a.cache.Set(ctx, key, a.storedUsername(username), identity, a.cfg.cacheTTL)
	case errors.Is(err, ErrInvalidCredentials):
		cerr = a.cache.Set(ctx, key, a.storedUsername(username), nil, a.cfg.cacheNegativeTTL)
	default:
		return
	}

	if cerr != nil {
		a.warn("cache write failed", "error", cerr)
		a.cfg.metrics.CacheEvent(CacheError)
	}
}

// cacheName is the username as the cache keys it. Folding case here and
// nowhere else is deliberate: the directory decides how usernames compare
// when it matches them, and this package decides only whether two requests
// share a cache entry.
func (a *Client) cacheName(username string) string {
	if a.cfg.caseFoldUsername {
		return strings.ToLower(username)
	}

	return username
}

// storedUsername is the username as the cache store sees it.
//
// The key already hides the credential, but the username is passed
// alongside it in the clear so that InvalidateUser can find an account's
// entries without knowing the password. On a store that is shared,
// remote, or backed up, that username is personal data this package put
// there. WithCacheUsernameHashing replaces it with a keyed hash under the
// same secret: InvalidateUser still works, because it hashes the same way,
// and the store holds nothing anybody can read.
//
// What it costs is the ability to look in the cache and see who is in it,
// which is a real debugging affordance and the reason this is a choice
// rather than the default.
func (a *Client) storedUsername(username string) string {
	folded := a.cacheName(username)

	if !a.cfg.hashCacheUsernames {
		return folded
	}

	mac := hmac.New(sha256.New, a.cacheSecret)
	mac.Write([]byte("username\x00"))
	mac.Write([]byte(folded))

	return hex.EncodeToString(mac.Sum(nil))
}

func resultLabel(err error) string {
	switch {
	case err == nil:
		return ResultSuccess
	case errors.Is(err, ErrInvalidCredentials):
		return ResultInvalidCredentials
	case errors.Is(err, ErrTooManyAttempts):
		return ResultThrottled
	case errors.Is(err, ErrEmptyPassword),
		errors.Is(err, ErrEmptyUsername),
		errors.Is(err, ErrInvalidUsername),
		errors.Is(err, ErrInvalidPassword):
		return ResultRejected
	default:
		return ResultError
	}
}

// checkCredentials is everything that can be decided without the network.
//
// It runs before a connection is opened, which is the point: a request
// that cannot be a valid login should not cost a TCP handshake, and an
// empty password must never reach a Bind.
func (c *config) checkCredentials(username, password string) error {
	if err := c.checkUsername(username); err != nil {
		return err
	}

	if password == "" {
		return ErrEmptyPassword
	}

	if len(password) > c.passwordMaxLength {
		// A password longer than any directory will store is not a login
		// attempt. Refusing it here keeps a megabyte of nonsense from
		// becoming a megabyte on the wire, once per request, for as long
		// as somebody cares to send it.
		return fmt.Errorf(
			"%w: %d bytes exceeds the %d byte limit",
			ErrInvalidPassword, len(password), c.passwordMaxLength,
		)
	}

	return nil
}

func (c *config) checkUsername(username string) error {
	if strings.TrimSpace(username) == "" {
		return ErrEmptyUsername
	}

	if len(username) > c.usernameMaxLength {
		return fmt.Errorf(
			"%w: %d bytes exceeds the %d byte limit",
			ErrInvalidUsername, len(username), c.usernameMaxLength,
		)
	}

	if !utf8.ValidString(username) {
		return fmt.Errorf("%w: not valid UTF-8", ErrInvalidUsername)
	}

	for _, r := range username {
		// A control character in a username is never a username. It is a
		// NUL trying to truncate a C string somewhere downstream, or a
		// newline trying to forge a second line in a log.
		if r == 0 || unicode.IsControl(r) {
			return fmt.Errorf("%w: contains a control character", ErrInvalidUsername)
		}
	}

	return nil
}
