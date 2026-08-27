// Command cache-store implements the Cache interface, which is how several
// replicas share one cache.
//
//	go run ./examples/cache-store
//
// The store here keeps everything in a map and prints what it is asked, so
// that the contract is visible: opaque keys, an unhashed username
// alongside, a nil identity for a cached rejection, and errors that must
// never become an outage. A Redis or memcached implementation is the same
// shape with a client in place of the map.
//
// The other half of sharing a cache is WithCacheSecret. Keys are derived
// from the credential by HMAC under the authenticator's secret, and the
// default secret is random per process — so without a shared one, every
// replica derives a different key for the same login and the shared cache
// silently never hits.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const peopleDN = "ou=people,dc=example,dc=com"

// sharedStore is what a Redis-backed cache would look like, with a map
// standing in for the client. It is deliberately noisy.
type sharedStore struct {
	mu      sync.Mutex
	entries map[string]entry

	// down makes every operation fail, to show what a cache outage does.
	down bool
}

type entry struct {
	identity ldapauth.Identity
	username string
	expires  time.Time
}

var errStoreDown = errors.New("cache: connection refused")

func newSharedStore() *sharedStore {
	return &sharedStore{entries: map[string]entry{}}
}

// Get returns the cached outcome. A hit with a nil identity is a cached
// rejection, which is a different thing from a miss.
func (s *sharedStore) Get(_ context.Context, key string) (ldapauth.Identity, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.down {
		return nil, false, errStoreDown
	}

	// The key is raw HMAC output, not a string that is safe in a URL or a
	// Redis key — encode it.
	fmt.Printf("  GET %s…\n", hex.EncodeToString([]byte(key))[:16])

	held, ok := s.entries[key]
	if !ok || time.Now().After(held.expires) {
		delete(s.entries, key)

		return nil, false, nil
	}

	if held.identity == nil {
		return nil, true, nil
	}

	// Hand out a copy. A store that returned the value it holds would let
	// one caller's edit become every later caller's.
	return held.identity.Clone(), true, nil
}

// Set records an outcome. A nil identity records a rejection.
func (s *sharedStore) Set(
	_ context.Context,
	key, username string,
	identity ldapauth.Identity,
	ttl time.Duration,
) error {
	if ttl <= 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.down {
		return errStoreDown
	}

	outcome := "rejected"
	if identity != nil {
		outcome = "authenticated"
		identity = identity.Clone()
	}

	fmt.Printf("  SET %s… username=%q %s ttl=%s\n",
		hex.EncodeToString([]byte(key))[:16], username, outcome, ttl)

	s.entries[key] = entry{identity: identity, username: username, expires: time.Now().Add(ttl)}

	return nil
}

// InvalidateUser drops every entry for one account, whatever password
// keyed it. This is why the username is passed alongside the key.
func (s *sharedStore) InvalidateUser(_ context.Context, username string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dropped := 0

	for key, held := range s.entries {
		if held.username == username {
			delete(s.entries, key)
			dropped++
		}
	}

	return dropped, nil
}

// InvalidateAll empties the store.
func (s *sharedStore) InvalidateAll(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dropped := len(s.entries)
	s.entries = map[string]entry{}

	return dropped, nil
}

// Len reports the size, for Stats. A store that cannot answer cheaply
// should return an error rather than counting a million keys.
func (s *sharedStore) Len(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.entries), nil
}

func (s *sharedStore) setDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.down = down
}

func main() {
	// The secret every replica shares. In production this comes from a
	// secret manager, and it is a real secret: anybody holding it can
	// test a guessed credential against the cache offline.
	secret := []byte("a-shared-secret-of-at-least-16-bytes")

	store := newSharedStore()
	dir := directory()

	replica := func(name string) *ldapauth.Client {
		auth, err := ldapauth.New(
			ldapauth.WithURL("ldap://in-memory"),
			ldapauth.WithDialer(dir.Dialer()),
			ldapauth.WithDirectBind("uid={{username}},"+peopleDN),

			ldapauth.WithCache(30*time.Second),
			ldapauth.WithNegativeCache(5*time.Second),
			ldapauth.WithCacheStore(store),
			ldapauth.WithCacheSecret(secret),
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			os.Exit(1)
		}

		return auth
	}

	first, second := replica("first"), replica("second")

	defer func() { _ = first.Close() }()
	defer func() { _ = second.Close() }()

	ctx := context.Background()

	fmt.Println("first replica, cold:")
	authenticate(ctx, first, "alice", "s3cret")
	fmt.Printf("  binds so far: %d\n\n", len(dir.Binds()))

	fmt.Println("second replica, same credential — the shared secret makes the key match:")
	authenticate(ctx, second, "alice", "s3cret")
	fmt.Printf("  binds so far: %d\n\n", len(dir.Binds()))

	fmt.Println("a rejection is cached too, which is what keeps a stale password away from a lockout policy:")
	authenticate(ctx, first, "alice", "wrong")
	authenticate(ctx, second, "alice", "wrong")
	fmt.Println()

	fmt.Println("after a password change, drop the account's entries rather than waiting out the TTL:")
	dropped, _ := first.InvalidateUser(ctx, "alice")
	fmt.Printf("  invalidated %d entries\n\n", dropped)

	fmt.Println("and when the store is down, the directory answers instead:")
	store.setDown(true)
	authenticate(ctx, first, "alice", "s3cret")
	store.setDown(false)

	fmt.Printf("\ntotal binds: %d\n", len(dir.Binds()))
}

func authenticate(ctx context.Context, auth *ldapauth.Client, username, password string) {
	_, err := auth.Authenticate(ctx, username, password)

	switch {
	case err == nil:
		fmt.Printf("  %s authenticated\n", username)
	case errors.Is(err, ldapauth.ErrInvalidCredentials):
		fmt.Printf("  %s rejected\n", username)
	default:
		fmt.Printf("  %s failed: %v\n", username, err)
	}
}

func directory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User("uid=alice,"+peopleDN, "s3cret").
			With("uid", "alice").
			With("objectClass", "inetOrgPerson"),
	)
}
