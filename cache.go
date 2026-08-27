package ldapauth

import (
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"sync"
	"time"
)

// cache remembers authentication outcomes for a short while.
//
// The thing to understand about it is what is stored and what is not. The
// key is an HMAC-SHA-256 of the username and password under a key drawn
// from the system CSPRNG when the authenticator is built and never
// written down. The value is the outcome. A memory dump of a process
// using this cache yields no password and nothing a password can be
// recovered from, and the key does not survive the process, so two runs
// of the same program produce unrelated keys for the same credentials.
//
// What it costs is freshness: for the length of the TTL, a disabled
// account, a changed password, or a revoked group membership still works.
// MaxCacheTTL caps that at five minutes and there is no way to raise it.
type cache struct {
	// secret keys the HMAC. It is per-authenticator and per-process.
	secret []byte

	maxEntries int

	now func() time.Time

	mu      sync.Mutex
	entries map[string]*list.Element

	// order is the eviction order, oldest at the front. Reads do not
	// promote: this is a TTL cache with a size bound, not an LRU, and
	// promoting on read would keep a hot entry alive past nothing —
	// its expiry is absolute either way.
	order *list.List
}

type cacheEntry struct {
	key string

	// username is kept so that InvalidateUser can find the entries for
	// one account without knowing the password that keyed them.
	username string

	// principal is nil for a cached failure.
	principal *Principal

	expiresAt time.Time
}

func newCache(maxEntries int, now func() time.Time) (*cache, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}

	return &cache{
		secret:     secret,
		maxEntries: maxEntries,
		now:        now,
		entries:    make(map[string]*list.Element, maxEntries),
		order:      list.New(),
	}, nil
}

// key derives the cache key. The username is included in the hashed input
// as well as being stored alongside it, so that two accounts that happen
// to share a password do not share an entry.
func (c *cache) key(username, password string) string {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(username))
	mac.Write([]byte{0})
	mac.Write([]byte(password))

	return string(mac.Sum(nil))
}

// lookup returns the cached outcome: a principal on a cached success, and
// hit reporting whether anything was cached at all. A hit with a nil
// principal is a cached failure.
func (c *cache) lookup(username, password string) (p *Principal, hit bool) {
	key := c.key(username, password)

	c.mu.Lock()
	defer c.mu.Unlock()

	element, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	entry := element.Value.(*cacheEntry)

	if !c.now().Before(entry.expiresAt) {
		c.removeLocked(element)

		return nil, false
	}

	return entry.principal.clone(), true
}

// store records an outcome. A nil principal records a failure. A
// non-positive ttl records nothing, which is how negative caching is
// switched off.
func (c *cache) store(username, password string, p *Principal, ttl time.Duration) {
	if ttl <= 0 {
		return
	}

	key := c.key(username, password)

	entry := &cacheEntry{
		key:       key,
		username:  username,
		principal: p.clone(),
		expiresAt: c.now().Add(ttl),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.entries[key]; ok {
		c.order.Remove(existing)
		delete(c.entries, key)
	}

	c.entries[key] = c.order.PushBack(entry)

	for len(c.entries) > c.maxEntries {
		oldest := c.order.Front()
		if oldest == nil {
			break
		}

		c.removeLocked(oldest)
	}
}

// invalidateUser drops every entry for one account, whatever password
// keyed it. It is what an application calls when it has just changed
// somebody's password and would rather not wait out the TTL.
func (c *cache) invalidateUser(username string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	dropped := 0

	for element := c.order.Front(); element != nil; {
		next := element.Next()

		if entryOf(element).matches(username) {
			c.removeLocked(element)
			dropped++
		}

		element = next
	}

	return dropped
}

func (c *cache) invalidateAll() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	dropped := len(c.entries)

	c.entries = make(map[string]*list.Element, c.maxEntries)
	c.order.Init()

	return dropped
}

func (c *cache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}

// removeLocked drops an element. The caller holds the lock.
func (c *cache) removeLocked(element *list.Element) {
	delete(c.entries, entryOf(element).key)
	c.order.Remove(element)
}

func entryOf(element *list.Element) *cacheEntry {
	return element.Value.(*cacheEntry)
}

// matches compares usernames the way a directory would, case-insensitively.
// Invalidation erring towards dropping too much is correct; erring towards
// dropping too little would leave a changed password working.
func (e *cacheEntry) matches(username string) bool {
	return strings.EqualFold(e.username, username)
}
