package ldapauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// A ByteStore is a cache that holds bytes, which is what Redis and
// memcached actually are.
//
// It exists because [Cache] does not solve the hard half of a shared
// cache. Cache hands an implementation an [Identity] — a live Go value —
// and expects one back, so anybody writing a Redis store has to invent a
// serialisation, and anybody using [WithPrincipalMapper] with their own
// type has to invent one that round-trips it. Worse, a Cache holding
// decoded values trusts whatever the store returns: the key is an HMAC,
// but the value is not authenticated, so a directory-adjacent attacker
// who can write to the shared store can put an Identity carrying
// "cn=domain admins" under a key they cannot even read, and the next
// login that hits it is authorised as that. Deriving the key from a
// secret proves nothing about a value somebody else wrote.
//
// [WithSealedCacheStore] closes both. The authenticator serialises the
// identity itself, seals it with HMAC-SHA-256 under the same secret that
// derives the key, and verifies the seal on the way back — so a store is
// a place to put bytes, never a source of authorisation. A value that
// does not verify is treated as a miss and the directory is asked.
//
// Every method may return an error, and the authenticator treats one as
// a miss. Implementations must be safe for concurrent use.
type ByteStore interface {
	// Get returns the bytes stored under key, if any.
	Get(ctx context.Context, key string) (value []byte, hit bool, err error)

	// Set stores value under key for ttl. The username is passed
	// unhashed so that InvalidateUser can work; see [Cache] for what
	// that means for what a store holds.
	Set(ctx context.Context, key, username string, value []byte, ttl time.Duration) error

	// InvalidateUser drops every entry for one account and reports how
	// many it dropped.
	InvalidateUser(ctx context.Context, username string) (int, error)

	// InvalidateAll drops everything and reports how many it dropped.
	InvalidateAll(ctx context.Context) (int, error)

	// Len reports how many entries are held, for Stats. Return -1 if
	// that cannot be answered cheaply.
	Len(ctx context.Context) (int, error)
}

// ErrCacheTampered reports that a cached value failed its integrity
// check: the bytes under a key were not written by an authenticator
// holding this secret, or were changed after they were.
//
// It never reaches a caller of [Client.Authenticate] — a value that
// fails to verify is a miss, and the directory is asked. It reaches the
// logger and [Metrics.CacheEvent] under [CacheError], where it is worth
// an alert: nothing produces it by accident.
var ErrCacheTampered = errors.New("ldapauth: a cached value failed its integrity check")

// sealedCacheVersion prefixes every sealed value. It is covered by the
// MAC, so a value written by a future format cannot be replayed as this
// one, and bumping it invalidates the old format rather than misreading
// it.
const sealedCacheVersion = 1

// sealedCache is the [Cache] that [WithSealedCacheStore] builds: it
// serialises identities to JSON, authenticates them with HMAC-SHA-256,
// and refuses anything whose seal does not verify.
type sealedCache struct {
	store  ByteStore
	secret []byte
}

// sealedEntry is the serialised form. A rejection is Identity == nil,
// which JSON round-trips as null — so a rejection is sealed too, and
// cannot be forged into a success or the reverse.
type sealedEntry struct {
	Version  int            `json:"v"`
	Identity *wirePrincipal `json:"identity"`
}

// wirePrincipal is the on-the-wire shape of a [Principal].
//
// It is spelled out here rather than by tagging Principal, because the
// two answer different questions: Principal's own JSON encoding belongs
// to whoever puts one in an API response, and pinning it to this format
// would make a cache detail into their compatibility problem.
//
// Principal.Extra is deliberately absent. It holds whatever a custom
// PrincipalMapper put there, of whatever type; JSON would return it as a
// map[string]any, so a cached login would carry an Extra of a different
// type from an uncached one — the sort of difference that shows up in
// production and nowhere else. Dropping it is the honest option, and it
// is documented on [WithSealedCacheStore]: if Extra matters, either keep
// the cache in memory or write a [Cache] that encodes your own type.
type wirePrincipal struct {
	DN          string              `json:"dn"`
	Username    string              `json:"username,omitempty"`
	DisplayName string              `json:"display_name,omitempty"`
	Email       string              `json:"email,omitempty"`
	Groups      []string            `json:"groups,omitempty"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
}

func toWire(p *Principal) *wirePrincipal {
	return &wirePrincipal{
		DN:          p.DN,
		Username:    p.Username,
		DisplayName: p.DisplayName,
		Email:       p.Email,
		Groups:      p.Groups,
		Attributes:  p.Attributes,
	}
}

func (w *wirePrincipal) principal() *Principal {
	return &Principal{
		DN:          w.DN,
		Username:    w.Username,
		DisplayName: w.DisplayName,
		Email:       w.Email,
		Groups:      w.Groups,
		Attributes:  w.Attributes,
	}
}

// NewSealedCache wraps a [ByteStore] so that values are serialised and
// authenticated on the way in and verified on the way out.
//
// Most callers want [WithSealedCacheStore], which builds this with the
// authenticator's own cache secret so the two cannot drift apart. Use
// this directly only when composing caches by hand.
//
// The secret must be the same across every replica sharing the store,
// and it must be the same one passed to [WithCacheSecret], or replicas
// will reject each other's entries as tampered.
func NewSealedCache(store ByteStore, secret []byte) (Cache, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: NewSealedCache was given a nil store", ErrInvalidOption)
	}

	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: NewSealedCache was given an empty secret", ErrInvalidOption)
	}

	return &sealedCache{store: store, secret: append([]byte(nil), secret...)}, nil
}

// seal returns value prefixed by a MAC over the key and the value. The
// key is covered so that an entry cannot be moved to another key: a
// value that verifies under the key it was written to is the only thing
// that verifies at all.
func (c *sealedCache) seal(key string, value []byte) []byte {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(key))
	mac.Write([]byte{0})
	mac.Write(value)

	return append(mac.Sum(make([]byte, 0, sha256.Size+len(value))), value...)
}

// open verifies a sealed value and returns the payload.
func (c *sealedCache) open(key string, sealed []byte) ([]byte, error) {
	if len(sealed) < sha256.Size {
		return nil, ErrCacheTampered
	}

	tag, value := sealed[:sha256.Size], sealed[sha256.Size:]

	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(key))
	mac.Write([]byte{0})
	mac.Write(value)

	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, ErrCacheTampered
	}

	return value, nil
}

func (c *sealedCache) Get(ctx context.Context, key string) (Identity, bool, error) {
	sealed, hit, err := c.store.Get(ctx, key)
	if err != nil || !hit {
		return nil, false, err
	}

	value, err := c.open(key, sealed)
	if err != nil {
		// A miss, not a failure to authenticate: the caller logs this
		// and asks the directory, which is the only safe reading of a
		// value we cannot vouch for.
		return nil, false, err
	}

	var entry sealedEntry
	if err := json.Unmarshal(value, &entry); err != nil {
		return nil, false, fmt.Errorf("ldapauth: decoding a cached identity: %w", err)
	}

	if entry.Version != sealedCacheVersion {
		return nil, false, fmt.Errorf("ldapauth: a cached identity is version %d, want %d",
			entry.Version, sealedCacheVersion)
	}

	if entry.Identity == nil {
		return nil, true, nil
	}

	return entry.Identity.principal(), true, nil
}

func (c *sealedCache) Set(ctx context.Context, key, username string, identity Identity, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}

	entry := sealedEntry{Version: sealedCacheVersion}

	if identity != nil {
		// Only *Principal is serialisable here. A custom Identity from
		// WithPrincipalMapper is not something this package can encode,
		// and guessing at one would cache a value that decodes into
		// something other than what was authenticated. The write fails,
		// the authenticator logs it and counts it, and the login is
		// unaffected — a cache that cannot store is a cache that misses.
		principal, ok := identity.(*Principal)
		if !ok {
			return fmt.Errorf("ldapauth: a sealed cache can only store *Principal, got %T; "+
				"use WithCacheStore with your own serialisation for a custom Identity", identity)
		}

		entry.Identity = toWire(principal)
	}

	value, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("ldapauth: encoding an identity for the cache: %w", err)
	}

	return c.store.Set(ctx, key, username, c.seal(key, value), ttl)
}

func (c *sealedCache) InvalidateUser(ctx context.Context, username string) (int, error) {
	return c.store.InvalidateUser(ctx, username)
}

func (c *sealedCache) InvalidateAll(ctx context.Context) (int, error) {
	return c.store.InvalidateAll(ctx)
}

func (c *sealedCache) Len(ctx context.Context) (int, error) {
	return c.store.Len(ctx)
}
