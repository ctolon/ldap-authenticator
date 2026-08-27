package ldapauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

// byteStore is an in-memory [ldapauth.ByteStore] a test can reach into,
// standing in for the Redis that a hostile party has write access to.
type byteStore struct {
	mu      sync.Mutex
	entries map[string][]byte
	users   map[string]string
}

func newByteStore() *byteStore {
	return &byteStore{
		entries: make(map[string][]byte),
		users:   make(map[string]string),
	}
}

func (s *byteStore) Get(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.entries[key]

	return value, ok, nil
}

func (s *byteStore) Set(_ context.Context, key, username string, value []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[key] = value
	s.users[key] = username

	return nil
}

func (s *byteStore) InvalidateUser(_ context.Context, username string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dropped := 0

	for key, held := range s.users {
		if strings.EqualFold(held, username) {
			delete(s.entries, key)
			delete(s.users, key)

			dropped++
		}
	}

	return dropped, nil
}

func (s *byteStore) InvalidateAll(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dropped := len(s.entries)
	s.entries = make(map[string][]byte)
	s.users = make(map[string]string)

	return dropped, nil
}

func (s *byteStore) Len(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.entries), nil
}

// keys returns the store's keys, so a test can tamper with one without
// having to derive it.
func (s *byteStore) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys := make([]string, 0, len(s.entries))
	for key := range s.entries {
		keys = append(keys, key)
	}

	return keys
}

func (s *byteStore) put(key string, value []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[key] = value
}

// sealedSecret is a fixed secret, the way a deployment would take one
// from a secret manager and give the same to every replica.
var sealedSecret = []byte("0123456789abcdef0123456789abcdef")

func TestASealedCacheServesWhatItWrote(t *testing.T) {
	t.Parallel()

	store := newByteStore()
	dir := newDirectory()

	auth := searchAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheSecret(sealedSecret),
		ldapauth.WithSealedCacheStore(store),
	)

	first, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	binds := len(dir.Binds())

	second, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("the second Authenticate: %v", err)
	}

	if len(dir.Binds()) != binds {
		t.Errorf("the second login bound %d more times; the sealed entry should have served it",
			len(dir.Binds())-binds)
	}

	// The round trip has to preserve the identity, or a cached login is
	// a different login.
	if first.GetDN() != second.GetDN() {
		t.Errorf("DN = %q from the cache, want %q", second.GetDN(), first.GetDN())
	}

	if strings.Join(first.GetGroups(), ",") != strings.Join(second.GetGroups(), ",") {
		t.Errorf("groups = %v from the cache, want %v", second.GetGroups(), first.GetGroups())
	}
}

func TestASealedCacheRefusesAForgedIdentity(t *testing.T) {
	t.Parallel()

	// The threat this exists for: somebody with write access to the
	// shared store, and no ability to read it, writing an identity that
	// grants themselves a group. The key is an HMAC so they cannot
	// address a particular login — but they do not need to, if any
	// unverified value is trusted.
	store := newByteStore()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheSecret(sealedSecret),
		ldapauth.WithSealedCacheStore(store),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	forged, err := json.Marshal(map[string]any{
		"v": 1,
		"identity": map[string]any{
			"dn":       "uid=alice,ou=people,dc=corp,dc=example",
			"username": "alice",
			"groups":   []string{"domain admins"},
		},
	})
	if err != nil {
		t.Fatalf("building the forgery: %v", err)
	}

	for _, key := range store.keys() {
		store.put(key, forged)
	}

	identity, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate after tampering: %v", err)
	}

	// The forgery is unsealed, so it is a miss and the directory
	// answers. What must never happen is the forged group arriving.
	if identity.InGroup("domain admins") {
		t.Fatal("a forged cache entry granted a group the directory never returned")
	}
}

func TestASealedCacheRefusesAValueMovedToAnotherKey(t *testing.T) {
	t.Parallel()

	// Sealing the value alone would not be enough: a valid entry copied
	// from one key to another verifies, and an attacker who cannot forge
	// a value can still move one. The key is covered by the MAC for
	// exactly this.
	store := newByteStore()

	sealed, err := ldapauth.NewSealedCache(store, sealedSecret)
	if err != nil {
		t.Fatalf("NewSealedCache: %v", err)
	}

	ctx := testContext(t)

	admin := &ldapauth.Principal{DN: "uid=root,dc=corp", Groups: []string{"admins"}}
	if err := sealed.Set(ctx, "key-a", "root", admin, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	value, hit, err := store.Get(ctx, "key-a")
	if err != nil || !hit {
		t.Fatalf("the store did not hold key-a: hit=%v err=%v", hit, err)
	}

	store.put("key-b", value)

	if _, hit, err := sealed.Get(ctx, "key-b"); hit {
		t.Error("a value moved to another key verified")
	} else if !errors.Is(err, ldapauth.ErrCacheTampered) {
		t.Errorf("error = %v, want ErrCacheTampered", err)
	}
}

func TestASealedCacheRefusesAnotherSecretsEntries(t *testing.T) {
	t.Parallel()

	// A replica configured with the wrong secret must not accept the
	// others' entries. It will also derive different keys, so this is
	// belt and braces — but a shared cache is exactly where a mistake
	// like this is invisible until it matters.
	store := newByteStore()
	ctx := testContext(t)

	writer, err := ldapauth.NewSealedCache(store, sealedSecret)
	if err != nil {
		t.Fatalf("NewSealedCache: %v", err)
	}

	if err := writer.Set(ctx, "key", "alice", &ldapauth.Principal{DN: "uid=alice"}, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	reader, err := ldapauth.NewSealedCache(store, []byte("fedcba9876543210fedcba9876543210"))
	if err != nil {
		t.Fatalf("NewSealedCache: %v", err)
	}

	if _, hit, err := reader.Get(ctx, "key"); hit {
		t.Error("an entry sealed under another secret verified")
	} else if !errors.Is(err, ldapauth.ErrCacheTampered) {
		t.Errorf("error = %v, want ErrCacheTampered", err)
	}
}

func TestASealedCacheSealsARejection(t *testing.T) {
	t.Parallel()

	// A cached rejection is an authentication decision too. If only
	// successes were sealed, a rejection could be replaced by a success
	// — or, more quietly, a success could be turned into a lockout.
	store := newByteStore()
	ctx := testContext(t)

	sealed, err := ldapauth.NewSealedCache(store, sealedSecret)
	if err != nil {
		t.Fatalf("NewSealedCache: %v", err)
	}

	if err := sealed.Set(ctx, "key", "alice", nil, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	identity, hit, err := sealed.Get(ctx, "key")
	if err != nil || !hit {
		t.Fatalf("the rejection did not come back: hit=%v err=%v", hit, err)
	}

	if identity != nil {
		t.Errorf("identity = %v, want nil for a cached rejection", identity)
	}

	store.put("key", []byte(`{"v":1,"identity":{"dn":"uid=alice","groups":["admins"]}}`))

	if _, hit, err := sealed.Get(ctx, "key"); hit {
		t.Error("a rejection was replaced by an unsealed success")
	} else if !errors.Is(err, ldapauth.ErrCacheTampered) {
		t.Errorf("error = %v, want ErrCacheTampered", err)
	}
}

func TestASealedCacheRefusesATruncatedValue(t *testing.T) {
	t.Parallel()

	store := newByteStore()
	ctx := testContext(t)

	sealed, err := ldapauth.NewSealedCache(store, sealedSecret)
	if err != nil {
		t.Fatalf("NewSealedCache: %v", err)
	}

	for name, value := range map[string][]byte{
		"empty":      {},
		"short":      []byte("nope"),
		"tag only":   make([]byte, 32),
		"no payload": append(make([]byte, 32), 0),
	} {
		store.put("key", value)

		if _, hit, err := sealed.Get(ctx, "key"); hit {
			t.Errorf("a %s value verified", name)
		} else if err == nil {
			t.Errorf("a %s value produced no error", name)
		}
	}
}

func TestASealedCacheRefusesACustomIdentity(t *testing.T) {
	t.Parallel()

	// It cannot encode one, and guessing would cache something other
	// than what was authenticated. Failing the write is the honest
	// answer; the authenticator treats it as a cache that missed.
	sealed, err := ldapauth.NewSealedCache(newByteStore(), sealedSecret)
	if err != nil {
		t.Fatalf("NewSealedCache: %v", err)
	}

	err = sealed.Set(testContext(t), "key", "alice", customIdentity{}, time.Minute)
	if err == nil {
		t.Fatal("Set accepted an identity it cannot serialise")
	}

	if !strings.Contains(err.Error(), "WithCacheStore") {
		t.Errorf("the error does not point at the way out: %v", err)
	}
}

func TestACustomIdentityDoesNotBreakALoginAgainstASealedCache(t *testing.T) {
	t.Parallel()

	// The write fails on every login. That must cost a cache hit and
	// nothing else.
	auth := searchAuth(t, newDirectory(),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheSecret(sealedSecret),
		ldapauth.WithSealedCacheStore(newByteStore()),
		ldapauth.WithPrincipalMapper(ldapauth.PrincipalMapperFunc(
			func(ldapauth.Mapping) (ldapauth.Identity, error) {
				return customIdentity{}, nil
			},
		)),
	)

	for i := range 2 {
		if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
			t.Fatalf("Authenticate %d: %v", i, err)
		}
	}
}

func TestASealedCacheRefusesToBeBuiltWithout(t *testing.T) {
	t.Parallel()

	if _, err := ldapauth.NewSealedCache(nil, sealedSecret); !errors.Is(err, ldapauth.ErrInvalidOption) {
		t.Errorf("a nil store gave %v, want ErrInvalidOption", err)
	}

	if _, err := ldapauth.NewSealedCache(newByteStore(), nil); !errors.Is(err, ldapauth.ErrInvalidOption) {
		t.Errorf("an empty secret gave %v, want ErrInvalidOption", err)
	}
}

func TestTheTwoCacheStoreOptionsAreExclusive(t *testing.T) {
	t.Parallel()

	_, err := ldapauth.New(
		ldapauth.WithURL("ldaps://directory.example:636"),
		ldapauth.WithDirectBind("uid={{username}},dc=corp"),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheStore(ldapauth.NewMemoryCache(16, nil)),
		ldapauth.WithSealedCacheStore(newByteStore()),
	)

	if !errors.Is(err, ldapauth.ErrInvalidOption) {
		t.Errorf("err = %v, want ErrInvalidOption", err)
	}
}

func TestATagIsNotValidOutsideItsPurpose(t *testing.T) {
	t.Parallel()

	// The unit-level statement of what derive.go is for: the same master
	// secret, the same two strings, and the login path's key derivation
	// still does not produce something the seal will accept.
	store := newByteStore()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheSecret(sealedSecret),
		ldapauth.WithSealedCacheStore(store),
	)

	ctx := testContext(t)

	if _, err := auth.Authenticate(ctx, "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	keys := store.keys()
	if len(keys) != 1 {
		t.Fatalf("the store holds %d entries, want one", len(keys))
	}

	value, _, err := store.Get(ctx, keys[0])
	if err != nil {
		t.Fatalf("reading the entry: %v", err)
	}

	// The seal tag is the first 32 bytes. If the two derivations shared a
	// key and a message shape, this hex would be a cache key the login
	// path could also have produced — that is the whole attack.
	tag := hex.EncodeToString(value[:sha256.Size])

	if tag == keys[0] {
		t.Fatal("the seal tag equals the cache key: the two derivations have collapsed into one")
	}
}

// TestTheSealCannotBeForgedThroughTheKeyDerivation is the regression test
// for a cross-protocol forgery against WithSealedCacheStore.
//
// The cache key and the seal tag were both HMAC-SHA-256 under the same
// secret over the same shape — A, a NUL, then B:
//
//	key  = HMAC(secret, username ‖ 0 ‖ password)
//	tag  = HMAC(secret, key      ‖ 0 ‖ value)
//
// With no domain separation between them, the login path is a signing
// oracle for the seal. An attacker who can read and write the shared store
// submits a login whose username is the victim's cache key and whose
// password is the forged payload; the login fails, the negative cache
// writes an entry, and the key of that entry is hex(HMAC(secret, K ‖ 0 ‖
// V)) — which is exactly the seal tag for that payload under that key.
// Decoding it and writing tag‖value back under K forges an identity.
//
// The store here is honest. What is under test is whether the package
// hands out a tag for bytes it never sealed.
func TestTheSealCannotBeForgedThroughTheKeyDerivation(t *testing.T) {
	t.Parallel()

	store := newByteStore()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheSecret(sealedSecret),
		ldapauth.WithSealedCacheStore(store),
	)

	ctx := testContext(t)

	// The victim logs in, so the store holds one entry under their key.
	if _, err := auth.Authenticate(ctx, "alice", alicePassword); err != nil {
		t.Fatalf("the victim's login: %v", err)
	}

	keys := store.keys()
	if len(keys) != 1 {
		t.Fatalf("the store holds %d entries, want the victim's one", len(keys))
	}

	victimKey := keys[0]

	// The payload the attacker wants believed, in the exact serialised
	// form the sealed cache reads back.
	forgedValue, err := json.Marshal(map[string]any{
		"v": 1,
		"identity": map[string]any{
			"dn":       "uid=alice,ou=people,dc=corp,dc=example",
			"username": "alice",
			"groups":   []string{"domain admins"},
		},
	})
	if err != nil {
		t.Fatalf("building the payload: %v", err)
	}

	// The oracle: a login whose username is the victim's key and whose
	// password is the payload. It fails, and the negative cache writes an
	// entry keyed by the MAC of exactly those two strings.
	if _, err := auth.Authenticate(ctx, victimKey, string(forgedValue)); err == nil {
		t.Fatal("the oracle login succeeded, which this test did not arrange")
	}

	var oracleKey string

	for _, key := range store.keys() {
		if key != victimKey {
			oracleKey = key

			break
		}
	}

	if oracleKey == "" {
		t.Skip("no negative-cache entry was written; the oracle does not exist on this path")
	}

	tag, err := hex.DecodeString(oracleKey)
	if err != nil {
		t.Fatalf("the cache key is not hex: %v", err)
	}

	// If the two derivations share a domain, this is a valid seal.
	store.put(victimKey, append(tag, forgedValue...))

	identity, err := auth.Authenticate(ctx, "alice", alicePassword)
	if err != nil {
		t.Fatalf("the victim's second login: %v", err)
	}

	if identity.InGroup("domain admins") {
		t.Fatal("FORGED: the login path signed a cache value it never sealed, " +
			"and the sealed cache accepted it")
	}
}
