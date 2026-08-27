package ldapauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// pool holds connections that are bound as the service account.
//
// It exists only when the configuration searches the directory: a direct
// bind that looks nothing up never builds one. What it pools is the
// *service* identity and nothing else — a user bind always gets its own
// connection, which is closed afterwards. Rebinding a pooled connection as
// the user would leave it carrying that user's identity for whichever
// request took it next, and that is an authorisation bypass, not an
// optimisation.
type pool struct {
	cfg     *config
	dialer  Dialer
	servers *serverSet

	// tokens is the size limit, expressed as a semaphore rather than a
	// counter so that waiting for a free slot is selectable against the
	// caller's context. It starts full.
	tokens chan struct{}

	// warming serialises the top-up. Two of them at once would not break
	// anything — the token semaphore still bounds the size — but they
	// would each open connections the other was about to, and the pool
	// would sit above its floor for no reason.
	warming atomic.Bool

	mu     sync.Mutex
	idle   []*pooledConn
	inUse  int
	closed bool

	// janitorStop and janitorDone bracket the background reaper.
	janitorStop chan struct{}
	janitorDone chan struct{}

	// life is the authenticator's own context, not any caller's. The
	// reaper's top-up runs under it so that shutting down stops it.
	life context.Context
}

// pooledConn is a connection with the bookkeeping the pool needs to decide
// whether it is still worth keeping.
type pooledConn struct {
	Conn

	url string

	createdAt time.Time

	idleSince time.Time
}

func newPool(life context.Context, cfg *config, dialer Dialer, servers *serverSet) *pool {
	p := &pool{
		cfg:         cfg,
		dialer:      dialer,
		servers:     servers,
		tokens:      make(chan struct{}, cfg.poolSize),
		janitorStop: make(chan struct{}),
		janitorDone: make(chan struct{}),
		life:        life,
	}

	for range cfg.poolSize {
		p.tokens <- struct{}{}
	}

	go p.janitor()

	return p
}

// acquire takes a connection out of the pool, opening and binding a fresh
// one when there is none to reuse.
//
// The size limit is taken first and released on every failure path, so a
// dial that fails does not permanently consume a slot — a pool that leaked
// slots on failure would shrink to nothing during the outage it is meant
// to survive.
func (p *pool) acquire(ctx context.Context) (*pooledConn, error) {
	// Checked before the select rather than only inside it. A select with
	// two ready cases picks at random, so a caller who has already given
	// up would get a connection half the time — and the failure that
	// follows would be a different one on every run.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPoolExhausted, err)
	}

	select {
	case <-p.tokens:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrPoolExhausted, ctx.Err())
	}

	conn, err := p.take(ctx)
	if err != nil {
		p.tokens <- struct{}{}

		return nil, err
	}

	p.mu.Lock()
	p.inUse++
	inUse, idle := p.inUse, len(p.idle)
	p.mu.Unlock()

	p.cfg.metrics.PoolStats(inUse, idle)

	return conn, nil
}

// take returns a usable connection, reusing an idle one when there is a
// live one to reuse.
func (p *pool) take(ctx context.Context) (*pooledConn, error) {
	for {
		conn := p.popIdle()
		if conn == nil {
			break
		}

		if !p.usable(conn) {
			p.discard(conn, "expired")

			continue
		}

		if p.cfg.poolHealthCheck {
			if _, err := conn.WhoAmI(nil); err != nil {
				p.discard(conn, "unhealthy")

				continue
			}
		}

		return conn, nil
	}

	return p.open(ctx)
}

// open dials a new connection and binds it as the service account.
func (p *pool) open(ctx context.Context) (*pooledConn, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()

	if closed {
		return nil, ErrClosed
	}

	conn, url, err := p.servers.dial(ctx, p.dialer)
	if err != nil {
		return nil, err
	}

	p.cfg.metrics.ConnOpened(url)

	if !p.cfg.anonymousService {
		if err := conn.Bind(p.cfg.serviceDN, p.cfg.servicePassword); err != nil {
			_ = conn.Close()
			p.cfg.metrics.ConnClosed("error")

			// A server that accepted the connection and then could not
			// take the service bind is a server to move on from. Not for
			// a rejected credential, though: that is the same wrong
			// password on every replica, and penalising would empty the
			// rotation over a configuration mistake.
			if retriable(err) {
				p.servers.penalise(url)
			}

			return nil, &AuthError{
				Op:         "service bind",
				URL:        url,
				Username:   p.cfg.serviceDN,
				ResultCode: resultCode(err),
				Err:        err,
			}
		}
	}

	now := p.cfg.now()

	return &pooledConn{
		Conn:      conn,
		url:       url,
		createdAt: now,
		idleSince: now,
	}, nil
}

// release returns a connection to the pool, or closes it when the caller
// reports that the operation on it failed.
//
// A connection whose operation errored is never reused. Distinguishing a
// protocol-level rejection from a broken connection would need to unpick
// every result code the directory might have sent, and the cost of being
// wrong — a wedged connection handed to the next request — is much higher
// than the cost of one extra dial.
func (p *pool) release(conn *pooledConn, opErr error) {
	if conn == nil {
		return
	}

	defer func() { p.tokens <- struct{}{} }()

	p.mu.Lock()
	p.inUse--
	closed := p.closed
	p.mu.Unlock()

	switch {
	case closed:
		p.discard(conn, "closed")
	case opErr != nil && !errors.Is(opErr, ErrInvalidCredentials):
		p.discard(conn, "error")
	case conn.IsClosing() || !p.usable(conn):
		p.discard(conn, "expired")
	default:
		conn.idleSince = p.cfg.now()

		p.mu.Lock()
		p.idle = append(p.idle, conn)
		inUse, idle := p.inUse, len(p.idle)
		p.mu.Unlock()

		p.cfg.metrics.PoolStats(inUse, idle)
	}
}

// usable reports whether a connection is still within its lifetime and
// idle budget.
func (p *pool) usable(conn *pooledConn) bool {
	now := p.cfg.now()

	if p.cfg.poolMaxLifetime > 0 && now.Sub(conn.createdAt) >= p.cfg.poolMaxLifetime {
		return false
	}

	if p.cfg.poolMaxIdleTime > 0 && now.Sub(conn.idleSince) >= p.cfg.poolMaxIdleTime {
		return false
	}

	return !conn.IsClosing()
}

func (p *pool) popIdle() *pooledConn {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.idle) == 0 {
		return nil
	}

	// Take from the back: the most recently returned connection is the
	// one most likely to still be alive, and taking from the front would
	// keep every connection just barely warm instead of letting the
	// surplus go idle and be reaped.
	last := len(p.idle) - 1
	conn := p.idle[last]
	p.idle[last] = nil
	p.idle = p.idle[:last]

	return conn
}

func (p *pool) discard(conn *pooledConn, reason string) {
	_ = conn.Close()
	p.cfg.metrics.ConnClosed(reason)
}

// warm opens connections until the pool holds minIdle idle ones.
//
// The subtlety, and the reason this is not a loop of acquire-then-release:
// releasing a connection puts it back where the next acquire will find it,
// so acquiring and releasing minIdle times opens exactly one connection
// and hands it round in a circle. Every connection has to be held until
// they are all open.
//
// It runs in the background from New, and again after the reaper closes an
// idle connection — a floor that is only established once is a floor that
// erodes over the first quiet hour. Failures are the pool's own business:
// a directory that is not up yet is a reason for the first login to fail,
// not for the process to.
func (p *pool) warm(ctx context.Context) {
	if p.cfg.poolMinIdle <= 0 {
		return
	}

	if !p.warming.CompareAndSwap(false, true) {
		return
	}

	defer p.warming.Store(false)

	p.mu.Lock()
	held := len(p.idle)
	closed := p.closed
	p.mu.Unlock()

	if closed || held >= p.cfg.poolMinIdle {
		return
	}

	opened := make([]*pooledConn, 0, p.cfg.poolMinIdle-held)

	defer func() {
		for _, conn := range opened {
			p.release(conn, nil)
		}
	}()

	for range p.cfg.poolMinIdle - held {
		conn, err := p.acquire(ctx)
		if err != nil {
			return
		}

		opened = append(opened, conn)
	}
}

// janitor closes connections that have aged out while nothing was using
// the pool. Expiry is also checked on every acquire and release; the
// janitor is what makes it happen when there is no traffic to check it.
func (p *pool) janitor() {
	defer close(p.janitorDone)

	interval := p.reapInterval()
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.janitorStop:
			return
		case <-ticker.C:
			if p.reap() > 0 {
				// The floor has to be re-established, or a quiet night
				// leaves the morning's first burst paying for every
				// connection it needs.
				p.warm(p.life)
			}
		}
	}
}

func (p *pool) reapInterval() time.Duration {
	budget := p.cfg.poolMaxIdleTime

	if p.cfg.poolMaxLifetime > 0 && (budget == 0 || p.cfg.poolMaxLifetime < budget) {
		budget = p.cfg.poolMaxLifetime
	}

	if budget <= 0 {
		return 0
	}

	return min(max(budget/4, time.Second), time.Minute)
}

// reap closes idle connections that have aged out and reports how many.
func (p *pool) reap() int {
	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()

		return 0
	}

	keep := p.idle[:0]

	var expired []*pooledConn

	for _, conn := range p.idle {
		if p.usable(conn) {
			keep = append(keep, conn)

			continue
		}

		expired = append(expired, conn)
	}

	for i := len(keep); i < len(p.idle); i++ {
		p.idle[i] = nil
	}

	p.idle = keep
	p.mu.Unlock()

	for _, conn := range expired {
		p.discard(conn, "idle")
	}

	return len(expired)
}

// close shuts the pool down. Connections that are out on loan are not
// waited for; they are closed by release, which sees the closed flag.
func (p *pool) close() error {
	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()

		return nil
	}

	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	close(p.janitorStop)
	<-p.janitorDone

	var errs []error

	for _, conn := range idle {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}

		p.cfg.metrics.ConnClosed("closed")
	}

	return errors.Join(errs...)
}

// stats reports occupancy for Stats.
func (p *pool) stats() (inUse, idle int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.inUse, len(p.idle)
}
