package ldapauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// An Authenticator verifies credentials against an LDAP directory.
//
// Build one per directory at startup and share it: it is safe for
// concurrent use, it owns the connection pool, and constructing one
// validates the whole configuration. Close it when the process is done
// with it.
type Authenticator struct {
	cfg *config

	dialer Dialer

	servers *serverSet

	// pool holds service-account connections. It is nil when the
	// configuration never searches — a direct bind with no attributes and
	// no groups needs no second identity.
	pool *pool

	// cache is nil unless WithCache was given.
	cache *cache

	closed chan struct{}

	closeOnce sync.Once
}

// New builds an Authenticator from the given options.
//
// It validates everything it can before returning: the URLs parse, the
// templates have the placeholders they need, the strategy is one of the
// two and not both, the numbers are in range, and TLS is either configured
// or explicitly declined. It does not talk to the directory — a directory
// that is briefly down should not stop a process from starting. Use
// HealthCheck for that.
//
// The minimum useful configuration is a URL and a strategy:
//
//	auth, err := ldapauth.New(
//	    ldapauth.WithURL("ldaps://dc1.corp.example:636"),
//	    ldapauth.WithDirectBind("uid={{username}},ou=people,dc=corp,dc=example"),
//	)
func New(opts ...Option) (*Authenticator, error) {
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

	a := &Authenticator{
		cfg:     cfg,
		dialer:  cfg.dialer,
		servers: newServerSet(cfg.urls, cfg.failoverPolicy, cfg.failoverCooldown, cfg.now),
		closed:  make(chan struct{}),
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
		a.pool = newPool(cfg, a.dialer, a.servers)

		if cfg.poolMinIdle > 0 {
			// Warming happens in the background, and its failures are the
			// pool's own business. A directory that is not up yet is a
			// reason for the first login to fail, not for the process to.
			go a.pool.warm(context.Background())
		}
	}

	if cfg.cacheEnabled {
		c, err := newCache(cfg.cacheMaxEntries, cfg.now)
		if err != nil {
			return nil, fmt.Errorf("ldapauth: initialising cache: %w", err)
		}

		a.cache = c
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
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*Principal, error) {
	started := a.cfg.now()

	p, err := a.authenticate(ctx, username, password)

	a.cfg.metrics.AuthAttempt(resultLabel(err), a.cfg.now().Sub(started))

	return p, err
}

func (a *Authenticator) authenticate(ctx context.Context, username, password string) (*Principal, error) {
	if err := a.alive(); err != nil {
		return nil, err
	}

	if err := a.cfg.checkCredentials(username, password); err != nil {
		return nil, err
	}

	ctx, cancel := a.withTimeout(ctx)
	defer cancel()

	if p, hit := a.fromCache(username, password); hit {
		if p == nil {
			return nil, &AuthError{
				Op:       "cache",
				Username: a.cfg.safeUsername(username),
				Err:      ErrInvalidCredentials,
			}
		}

		return p, nil
	}

	var principal *Principal

	err := a.withRetry(ctx, "authenticate", func(ctx context.Context) error {
		p, err := a.once(ctx, username, password)
		if err != nil {
			return err
		}

		principal = p

		return nil
	})

	a.remember(username, password, principal, err)

	if err != nil {
		a.debug("authentication failed", "username", a.cfg.safeUsername(username), "error", err)

		return nil, err
	}

	a.debug("authentication succeeded",
		"username", a.cfg.safeUsername(username),
		"dn", principal.DN,
		"groups", len(principal.Groups),
	)

	return principal, nil
}

// once is a single attempt: bind, read, resolve groups. Everything that
// wraps it — validation, caching, retry, metrics — lives above.
func (a *Authenticator) once(ctx context.Context, username, password string) (*Principal, error) {
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

	groups, err := a.resolveGroups(ctx, r, username)
	if err != nil {
		return nil, err
	}

	p := a.cfg.newPrincipal(username, r.dn, r.entry)
	p.Groups = groups

	return p, nil
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
func (a *Authenticator) Lookup(ctx context.Context, username string) (*Principal, error) {
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

	var principal *Principal

	err := a.withRetry(ctx, "lookup", func(ctx context.Context) error {
		r, err := a.lookupOnce(ctx, username)
		if err != nil {
			return err
		}

		defer r.close()

		groups, err := a.resolveGroups(ctx, r, username)
		if err != nil {
			return err
		}

		principal = a.cfg.newPrincipal(username, r.dn, r.entry)
		principal.Groups = groups

		return nil
	})
	if err != nil {
		return nil, err
	}

	return principal, nil
}

func (a *Authenticator) lookupOnce(ctx context.Context, username string) (*resolved, error) {
	if a.cfg.directBind() {
		dn := a.cfg.bindDN.expand(escapeDNValue, map[string]string{placeholderUsername: username})

		entry, err := a.withPooledConn(ctx, func(conn Conn) (*ldap.Entry, error) {
			return a.readEntry(conn, dn)
		})
		if err != nil {
			if resultCode(err) == ldap.LDAPResultNoSuchObject {
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
		return a.searchUser(conn, username)
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
func (a *Authenticator) HealthCheck(ctx context.Context) error {
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

		_, err = conn.WhoAmI(nil)

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
	if _, err := conn.WhoAmI(nil); err != nil && resultCode(err) == 0 {
		return fmt.Errorf("ldapauth: health check on %s: %w", url, err)
	}

	return nil
}

// InvalidateUser drops every cached entry for one account and reports how
// many it dropped. Call it after changing somebody's password or their
// group memberships, rather than waiting out the TTL. It is a no-op when
// caching is off.
func (a *Authenticator) InvalidateUser(username string) int {
	if a.cache == nil {
		return 0
	}

	return a.cache.invalidateUser(username)
}

// InvalidateAll empties the cache and reports how many entries it dropped.
func (a *Authenticator) InvalidateAll() int {
	if a.cache == nil {
		return 0
	}

	return a.cache.invalidateAll()
}

// Stats reports the authenticator's current occupancy. It is a snapshot
// for a metrics scrape or a debug endpoint; nothing in the package
// branches on it.
func (a *Authenticator) Stats() Stats {
	s := Stats{
		Servers:        len(a.cfg.urls),
		HealthyServers: a.servers.healthy(),
	}

	if a.pool != nil {
		s.PoolInUse, s.PoolIdle = a.pool.stats()
		s.PoolSize = a.cfg.poolSize
	}

	if a.cache != nil {
		s.CacheEntries = a.cache.size()
	}

	return s
}

// Close releases the pooled connections. Calls already in flight are not
// interrupted; they finish against connections that are closed on release.
// Close is idempotent, and every method returns ErrClosed afterwards.
func (a *Authenticator) Close() error {
	var err error

	a.closeOnce.Do(func() {
		close(a.closed)

		if a.pool != nil {
			err = a.pool.close()
		}

		if a.cache != nil {
			a.cache.invalidateAll()
		}

		a.info("ldap authenticator closed")
	})

	return err
}

func (a *Authenticator) alive() error {
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
func (a *Authenticator) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if a.cfg.requestTimeout <= 0 {
		return context.WithCancel(ctx)
	}

	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= a.cfg.requestTimeout {
		return context.WithCancel(ctx)
	}

	return context.WithTimeout(ctx, a.cfg.requestTimeout)
}

func (a *Authenticator) fromCache(username, password string) (*Principal, bool) {
	if a.cache == nil {
		return nil, false
	}

	p, hit := a.cache.lookup(a.cacheName(username), password)
	if !hit {
		a.cfg.metrics.CacheEvent(CacheMiss)

		return nil, false
	}

	if p == nil {
		a.cfg.metrics.CacheEvent(CacheNegativeHit)

		return nil, true
	}

	a.cfg.metrics.CacheEvent(CacheHit)

	return p, true
}

// remember stores an outcome. Only the two outcomes that are about this
// credential are cached: a success, and a rejection. A connection failure
// says nothing about whether the password is right, and caching it would
// serve an outage back to the caller for the length of the TTL.
func (a *Authenticator) remember(username, password string, p *Principal, err error) {
	if a.cache == nil {
		return
	}

	switch {
	case err == nil:
		a.cache.store(a.cacheName(username), password, p, a.cfg.cacheTTL)
	case errors.Is(err, ErrInvalidCredentials):
		a.cache.store(a.cacheName(username), password, nil, a.cfg.cacheNegativeTTL)
	}
}

// cacheName is the username as the cache keys it. Folding case here and
// nowhere else is deliberate: the directory decides how usernames compare
// when it matches them, and this package decides only whether two requests
// share a cache entry.
func (a *Authenticator) cacheName(username string) string {
	if a.cfg.caseFoldUsername {
		return strings.ToLower(username)
	}

	return username
}

func resultLabel(err error) string {
	switch {
	case err == nil:
		return ResultSuccess
	case errors.Is(err, ErrInvalidCredentials):
		return ResultInvalidCredentials
	case errors.Is(err, ErrEmptyPassword),
		errors.Is(err, ErrEmptyUsername),
		errors.Is(err, ErrInvalidUsername):
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
