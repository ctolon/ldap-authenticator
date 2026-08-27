package ldapauth

// Stats is a snapshot of an authenticator's occupancy, as returned by
// Stats. It is plain data: read it, publish it, and do not branch on it —
// the numbers are already stale by the time you have them.
type Stats struct {
	// Servers is how many URLs are configured.
	Servers int

	// HealthyServers is how many of them are not currently inside a
	// failure cooldown. A number below Servers means failover has been
	// used recently; a zero means every server has failed and the next
	// attempt will retry them all.
	HealthyServers int

	// PoolSize is the configured maximum, or zero when there is no pool.
	PoolSize int

	// PoolInUse is how many pooled connections are checked out.
	PoolInUse int

	// PoolIdle is how many are open and waiting.
	PoolIdle int

	// CacheEntries is how many outcomes are cached, or zero when caching
	// is off. It counts cached failures as well as cached successes.
	CacheEntries int
}
