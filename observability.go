package ldapauth

import (
	"log/slog"
	"time"
)

// The values passed as the result argument to Metrics.AuthAttempt. They
// are a closed set so that a metrics backend can safely use them as a
// label value without unbounded cardinality.
const (
	// ResultSuccess is a completed authentication, cache or directory.
	ResultSuccess = "success"

	// ResultInvalidCredentials is a bind the directory rejected, or a user
	// the directory does not have. The two are one result on purpose; see
	// ErrInvalidCredentials.
	ResultInvalidCredentials = "invalid_credentials"

	// ResultRejected is a request this package refused before touching the
	// network: an empty password, a username with a NUL in it.
	ResultRejected = "rejected"

	// ResultError is any other failure — the directory was unreachable,
	// the search failed, the context expired.
	ResultError = "error"
)

// The values passed as the event argument to Metrics.CacheEvent.
const (
	CacheHit         = "hit"
	CacheMiss        = "miss"
	CacheNegativeHit = "negative_hit"
	CacheEvicted     = "evicted"

	// CacheCoalesced is a request that waited on an identical
	// authentication already in flight instead of opening one of its own.
	CacheCoalesced = "coalesced"

	// CacheError is a cache that could not answer. The authenticator
	// treats it as a miss and asks the directory.
	CacheError = "error"
)

// Metrics receives counters and timings from the authenticator.
//
// It is an interface of hooks rather than a dependency on a metrics
// library, which is what lets this package keep its one-dependency
// promise. A Prometheus, OpenTelemetry, or statsd adapter is a few dozen
// lines on the caller's side; the README has one.
//
// Every method is called on the goroutine that did the work, so an
// implementation that blocks blocks an authentication. Do the cheap thing
// here and buffer if you must.
//
// Embed NoopMetrics in your implementation. Methods will be added to this
// interface in future minor versions as the package grows things worth
// counting, and an embedded NoopMetrics is what keeps that from breaking
// your build.
type Metrics interface {
	// AuthAttempt reports one completed call to Authenticate, with one of
	// the Result constants and how long it took.
	AuthAttempt(result string, d time.Duration)

	// CacheEvent reports one cache interaction, with one of the Cache
	// constants.
	CacheEvent(event string)

	// RetryScheduled reports that an operation failed with a retriable
	// error and will be tried again after delay.
	RetryScheduled(op string, attempt int, delay time.Duration)

	// ConnOpened reports a new connection to the directory.
	ConnOpened(url string)

	// ConnClosed reports a connection being discarded, with a short reason
	// such as "idle", "lifetime", "unhealthy", or "error".
	ConnClosed(reason string)

	// PoolStats reports the pool's occupancy after a checkout or return.
	PoolStats(inUse, idle int)
}

// NoopMetrics implements Metrics and does nothing. It is the default, and
// it is what implementations should embed so that methods added to Metrics
// in a later release do not break them.
type NoopMetrics struct{}

// AuthAttempt does nothing.
func (NoopMetrics) AuthAttempt(string, time.Duration) {}

// CacheEvent does nothing.
func (NoopMetrics) CacheEvent(string) {}

// RetryScheduled does nothing.
func (NoopMetrics) RetryScheduled(string, int, time.Duration) {}

// ConnOpened does nothing.
func (NoopMetrics) ConnOpened(string) {}

// ConnClosed does nothing.
func (NoopMetrics) ConnClosed(string) {}

// PoolStats does nothing.
func (NoopMetrics) PoolStats(int, int) {}

// discardLogger drops everything. It is the default logger, so the logging
// calls in the hot path need no nil check and no level check of their own.
var discardLogger = slog.New(slog.DiscardHandler)

// The logging helpers exist so that no call site has to remember the
// package's one logging rule: a username may appear in a log line
// (redacted, if the caller asked for that), and a password may not, ever.
// There is no helper here that takes a password, which is the cheapest way
// to guarantee none is written.

func (a *Client) debug(msg string, args ...any) {
	a.cfg.logger.Debug(msg, args...)
}

func (a *Client) info(msg string, args ...any) {
	a.cfg.logger.Info(msg, args...)
}

func (a *Client) warn(msg string, args ...any) {
	a.cfg.logger.Warn(msg, args...)
}

// safeUsername renders a username for a log line or an AuthError, honouring
// the redaction setting.
func (c *config) safeUsername(username string) string {
	if c.redactUsername {
		return "[redacted]"
	}

	return username
}
