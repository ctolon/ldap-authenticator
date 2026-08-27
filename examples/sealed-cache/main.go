// Command sealed-cache shares a cache between replicas without trusting
// what is in it.
//
//	go run ./examples/sealed-cache
//
// A ByteStore holds bytes, which is what Redis and memcached actually are:
// a Get, a Set, and two invalidations. The authenticator does the rest —
// it serialises the identity, seals it with HMAC-SHA-256 under the same
// secret that derives the key, and verifies that seal on the way back out.
//
// The reason to prefer this over WithCacheStore is the write side. A Cache
// is handed a decoded Identity and believed; the key is an HMAC, so nobody
// can address a particular login, but nothing at all protects the value.
// Anybody who can write to the store — a Redis with no auth on a flat
// network is the usual way — can put an identity carrying "domain admins"
// under a key of their choosing, and the login that lands on it is
// authorised as that.
//
// This program does exactly that, twice: once against a sealed cache and
// once with the seal stripped, so the difference is visible rather than
// asserted.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const peopleDN = "ou=people,dc=example,dc=com"

// redisish is a ByteStore with a map where the client would be. Every
// method may fail, and the authenticator treats a failure as a miss: a
// cache that is down must never be a directory that is down.
type redisish struct {
	mu      sync.Mutex
	entries map[string][]byte
	users   map[string]string
	expires map[string]time.Time
}

func newRedisish() *redisish {
	return &redisish{
		entries: map[string][]byte{},
		users:   map[string]string{},
		expires: map[string]time.Time{},
	}
}

func (s *redisish) Get(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if expiry, ok := s.expires[key]; ok && time.Now().After(expiry) {
		s.dropLocked(key)

		return nil, false, nil
	}

	value, ok := s.entries[key]

	return value, ok, nil
}

func (s *redisish) Set(_ context.Context, key, username string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// The key is hex: printable, fixed length, and a valid memcached key
	// without any encoding of your own. The value is opaque bytes with a
	// 32-byte tag on the front.
	fmt.Printf("  SET %s… username=%q %d bytes ttl=%s\n", key[:16], username, len(value), ttl)

	s.entries[key] = value
	s.users[key] = username
	s.expires[key] = time.Now().Add(ttl)

	return nil
}

// InvalidateUser is why the username travels alongside the key: the key is
// derived from the password, so an account's entries cannot be found
// without it.
func (s *redisish) InvalidateUser(_ context.Context, username string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dropped := 0

	for key, held := range s.users {
		if strings.EqualFold(held, username) {
			s.dropLocked(key)

			dropped++
		}
	}

	return dropped, nil
}

func (s *redisish) InvalidateAll(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dropped := len(s.entries)
	s.entries = map[string][]byte{}
	s.users = map[string]string{}
	s.expires = map[string]time.Time{}

	return dropped, nil
}

func (s *redisish) Len(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.entries), nil
}

func (s *redisish) dropLocked(key string) {
	delete(s.entries, key)
	delete(s.users, key)
	delete(s.expires, key)
}

// tamper overwrites every entry with an identity that grants a group the
// directory never returned — what an attacker with write access does.
func (s *redisish) tamper(value []byte) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key := range s.entries {
		s.entries[key] = value
	}

	return len(s.entries)
}

// forged is the attacker's payload: the serialised form this package uses,
// with a group added. It carries no valid tag, because producing one needs
// the secret.
var forged = []byte(`{"v":1,"identity":{"dn":"uid=alice,` + peopleDN + `","username":"alice","groups":["domain admins"]}}`)

func main() {
	// The secret every replica shares, from a secret manager in
	// production. It derives the keys and seals the values, so it is a
	// real credential: see docs/security.md.
	secret := []byte("a-shared-secret-of-at-least-32-bytes")

	store := newRedisish()
	dir := directory()

	replica := func(name string) *ldapauth.Client {
		auth, err := ldapauth.New(
			ldapauth.WithURL("ldap://in-memory"),
			ldapauth.WithDialer(dir.Dialer()),
			ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
			ldapauth.WithMemberOfGroups(),

			ldapauth.WithCache(30*time.Second),
			ldapauth.WithCacheSecret(secret),
			ldapauth.WithSealedCacheStore(store),
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
	report(ctx, first, "alice", "s3cret")
	fmt.Printf("  binds so far: %d\n\n", len(dir.Binds()))

	fmt.Println("second replica, same credential — the shared secret makes the key match,")
	fmt.Println("and the seal makes the value trustworthy:")
	report(ctx, second, "alice", "s3cret")
	fmt.Printf("  binds so far: %d\n\n", len(dir.Binds()))

	fmt.Printf("now somebody with write access to the store forges an identity:\n  %s\n\n", forged)

	overwritten := store.tamper(forged)

	fmt.Printf("overwriting %d %s…\n", overwritten, plural(overwritten, "entry", "entries"))

	fmt.Println("the seal does not verify, so it is a miss and the directory answers:")
	report(ctx, first, "alice", "s3cret")
	fmt.Printf("  binds so far: %d\n\n", len(dir.Binds()))

	fmt.Println("the same forgery against an unsealed store — WithCacheStore, no")
	fmt.Println("integrity check on the value — is believed:")
	unsealed(ctx, dir)

	fmt.Println()
	fmt.Println("nothing produces a failed seal by accident. Alert on Metrics.CacheEvent(CacheError).")
}

// unsealed shows the other half of the comparison: the same forged bytes,
// decoded by hand and handed straight to a plain Cache, are trusted.
func unsealed(ctx context.Context, dir *ldaptest.Directory) {
	store := &trusting{}

	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(dir.Dialer()),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithMemberOfGroups(),

		ldapauth.WithCache(30*time.Second),
		ldapauth.WithCacheStore(store),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unsealed: %v\n", err)
		os.Exit(1)
	}

	defer func() { _ = auth.Close() }()

	report(ctx, auth, "alice", "s3cret")
}

// trusting is a Cache that returns what an attacker wrote. It is what any
// Cache is, from the authenticator's point of view: a thing whose word is
// taken.
type trusting struct{}

func (t *trusting) Get(context.Context, string) (ldapauth.Identity, bool, error) {
	return &ldapauth.Principal{
		DN:       "uid=alice," + peopleDN,
		Username: "alice",
		Groups:   []string{"domain admins"},
	}, true, nil
}

func (t *trusting) Set(context.Context, string, string, ldapauth.Identity, time.Duration) error {
	return nil
}

func (t *trusting) InvalidateUser(context.Context, string) (int, error) { return 0, nil }
func (t *trusting) InvalidateAll(context.Context) (int, error)          { return 0, nil }
func (t *trusting) Len(context.Context) (int, error)                    { return 0, nil }

func report(ctx context.Context, auth ldapauth.Authenticator, username, password string) {
	identity, err := auth.Authenticate(ctx, username, password)

	switch {
	case err == nil:
		fmt.Printf("  %s authenticated, groups=%v", username, identity.GetGroups())

		if identity.InGroup("domain admins") {
			fmt.Print("  ← the forgery was believed")
		}

		fmt.Println()
	case errors.Is(err, ldapauth.ErrInvalidCredentials):
		fmt.Printf("  %s rejected\n", username)
	default:
		fmt.Printf("  %s failed: %v\n", username, err)
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}

	return many
}

func directory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User("uid=alice,"+peopleDN, "s3cret").
			With("uid", "alice").
			With("objectClass", "inetOrgPerson").
			With("memberOf", "cn=engineering,ou=groups,dc=example,dc=com"),
	)
}
