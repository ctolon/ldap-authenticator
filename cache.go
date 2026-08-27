package ldapauth

import (
	"container/list"
	"context"
	"crypto/rand"
	"strings"
	"sync"
	"time"
)

// cacheSecretLength is the size of the key that turns a credential into a
// cache key. Thirty-two bytes is HMAC-SHA-256's block-optimal length and
// well past the point where guessing is the attack anybody would choose.
const cacheSecretLength = 32

// randomSecret draws a cache secret from the system CSPRNG.
func randomSecret() ([]byte, error) {
	secret := make([]byte, cacheSecretLength)

	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}

	return secret, nil
}

// A Cache remembers authentication outcomes for a short while.
//
// The package ships an in-memory one, built by [WithCache]. Replace it with
// [WithCacheStore] when several replicas should share a cache — a Redis or
// memcached implementation is a few dozen lines against this interface.
//
// # What a Cache is given
//
// Keys are opaque. The authenticator derives each one as an HMAC of the
// username and password under a secret it holds, so an implementation
// never sees a credential and a cache dump never yields one. By default
// the secret is drawn from the system CSPRNG at startup, which makes keys
// per-process; [WithCacheSecret] sets a shared one, which is what a shared
// cache needs in order to be shared.
//
// The username is passed alongside the key, unhashed, so that
// InvalidateUser can work without knowing the password. If that is more
// than you want to store, hash it — the authenticator only ever passes the
// same string back to InvalidateUser.
//
// # Failure
//
// Every method may return an error, and the authenticator treats one as a
// miss: it logs it and asks the directory. A cache that is down must never
// be a directory that is down.
//
// Implementations must be safe for concurrent use.
type Cache interface {
	// Get returns the cached outcome for key. A hit with a nil Identity is
	// a cached rejection.
	Get(ctx context.Context, key string) (identity Identity, hit bool, err error)

	// Set records an outcome for ttl. A nil identity records a rejection.
	// A non-positive ttl records nothing.
	Set(ctx context.Context, key, username string, identity Identity, ttl time.Duration) error

	// InvalidateUser drops every entry for one account, whatever password
	// keyed it, and reports how many it dropped.
	InvalidateUser(ctx context.Context, username string) (int, error)

	// InvalidateAll drops everything and reports how many it dropped.
	InvalidateAll(ctx context.Context) (int, error)

	// Len reports how many entries are held, for Stats. An implementation
	// that cannot answer cheaply should return -1.
	Len(ctx context.Context) (int, error)
}

// memoryCache is the in-memory [Cache] this package builds by default.
//
// It is a TTL cache with a size bound, not an LRU: reads do not promote,
// because an entry's expiry is absolute either way and promoting on read
// would only keep a hot entry alive past nothing.
type memoryCache struct {
	maxEntries int

	now func() time.Time

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List
}

// NewMemoryCache returns the in-memory cache this package uses by default,
// bounded to maxEntries and reading time from now.
//
// It is exported so that a caller who wants the default behaviour with a
// different bound, or who is composing it with something else — a local
// cache in front of a shared one — does not have to write it again. Pass
// nil for now to use [time.Now].
func NewMemoryCache(maxEntries int, now func() time.Time) Cache {
	if maxEntries < 1 {
		maxEntries = DefaultCacheMaxEntries
	}

	if now == nil {
		now = time.Now
	}

	return &memoryCache{
		maxEntries: maxEntries,
		now:        now,
		entries:    make(map[string]*list.Element, maxEntries),
		order:      list.New(),
	}
}

type cacheEntry struct {
	key string

	// username is kept so that InvalidateUser can find the entries for one
	// account without knowing the password that keyed them.
	username string

	// identity is nil for a cached rejection.
	identity Identity

	expiresAt time.Time
}

func (c *memoryCache) Get(_ context.Context, key string) (Identity, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	element, ok := c.entries[key]
	if !ok {
		return nil, false, nil
	}

	entry := element.Value.(*cacheEntry)

	if !c.now().Before(entry.expiresAt) {
		c.removeLocked(element)

		return nil, false, nil
	}

	if entry.identity == nil {
		return nil, true, nil
	}

	return entry.identity.Clone(), true, nil
}

func (c *memoryCache) Set(_ context.Context, key, username string, identity Identity, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}

	entry := &cacheEntry{
		key:       key,
		username:  username,
		expiresAt: c.now().Add(ttl),
	}

	if identity != nil {
		entry.identity = identity.Clone()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.entries[key]; ok {
		c.removeLocked(existing)
	}

	c.entries[key] = c.order.PushBack(entry)

	for len(c.entries) > c.maxEntries {
		oldest := c.order.Front()
		if oldest == nil {
			break
		}

		c.removeLocked(oldest)
	}

	return nil
}

// InvalidateUser drops every entry for one account. The username
// comparison is case-insensitive, the way a directory would compare it:
// erring towards dropping too much is correct here, and erring the other
// way would leave a changed password working.
func (c *memoryCache) InvalidateUser(_ context.Context, username string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	dropped := 0

	for element := c.order.Front(); element != nil; {
		next := element.Next()

		if strings.EqualFold(element.Value.(*cacheEntry).username, username) {
			c.removeLocked(element)
			dropped++
		}

		element = next
	}

	return dropped, nil
}

func (c *memoryCache) InvalidateAll(context.Context) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	dropped := len(c.entries)

	c.entries = make(map[string]*list.Element, c.maxEntries)
	c.order.Init()

	return dropped, nil
}

func (c *memoryCache) Len(context.Context) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries), nil
}

// removeLocked drops an element. The caller holds the lock.
func (c *memoryCache) removeLocked(element *list.Element) {
	delete(c.entries, element.Value.(*cacheEntry).key)
	c.order.Remove(element)
}
