package ldapauth

// The escaping and template code is unexported, and it is the code most
// worth testing directly: everything else in the package is a
// rearrangement of round trips, but this is where a mistake is a
// vulnerability. Testing it through the public API would mean asserting on
// filter strings recovered from a fake directory, which is a slower way of
// asking the same question with more that can go wrong in between.

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestEscapeFilterValue(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"alice":     "alice",
		"*":         `\2a`,
		"*)(uid=*":  `\2a\29\28uid=\2a`,
		`a\b`:       `a\5cb`,
		"a(b)c":     `a\28b\29c`,
		"\x00":      `\00`,
		"héllo":     `h\c3\a9llo`,
		"":          "",
		"a b":       "a b",
		"cn=x,dc=y": "cn=x,dc=y",
	}

	for in, want := range cases {
		if got := escapeFilterValue(in); got != want {
			t.Errorf("escapeFilterValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEscapeDNValue(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"alice":           "alice",
		"a,b":             `a\,b`,
		"a+b":             `a\+b`,
		`a"b`:             `a\"b`,
		`a\b`:             `a\\b`,
		"a<b>c":           `a\<b\>c`,
		"a;b":             `a\;b`,
		"#lead":           `\#lead`,
		" lead":           `\ lead`,
		"trail ":          `trail\ `,
		"mid # fine":      "mid # fine",
		"\x00":            `\00`,
		"":                "",
		"admin,ou=admins": `admin\,ou=admins`,
	}

	for in, want := range cases {
		if got := escapeDNValue(in); got != want {
			t.Errorf("escapeDNValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEscapedDNParsesBackToOneComponent(t *testing.T) {
	t.Parallel()

	// The property that matters: whatever the username was, the DN it is
	// spliced into has exactly the components the template had. A username
	// that added a component would be a username that moved the entry into
	// another subtree.
	hostile := []string{
		"alice",
		"admin,ou=admins,dc=example,dc=com",
		`a\,b`,
		"a+b",
		`x"y`,
		"#hash",
		" space ",
		"semi;colon",
	}

	for _, username := range hostile {
		dn := "uid=" + escapeDNValue(username) + ",ou=people,dc=example,dc=com"

		parsed, err := ldap.ParseDN(dn)
		if err != nil {
			t.Errorf("username %q produced an unparseable DN %q: %v", username, dn, err)

			continue
		}

		if len(parsed.RDNs) != 4 {
			t.Errorf("username %q produced %d RDNs in %q, want 4", username, len(parsed.RDNs), dn)

			continue
		}

		if got := parsed.RDNs[0].Attributes[0].Value; got != username {
			t.Errorf("username %q round-tripped as %q", username, got)
		}
	}
}

func TestParseTemplate(t *testing.T) {
	t.Parallel()

	t.Run("expands placeholders", func(t *testing.T) {
		t.Parallel()

		tmpl, err := parseTemplate("uid={{username}},ou=people,{{base_dn}}", placeholderUsername, placeholderBaseDN)
		if err != nil {
			t.Fatalf("parseTemplate: %v", err)
		}

		got := tmpl.expand(verbatim, map[string]string{
			placeholderUsername: "alice",
			placeholderBaseDN:   "dc=example,dc=com",
		})

		if want := "uid=alice,ou=people,dc=example,dc=com"; got != want {
			t.Errorf("expand = %q, want %q", got, want)
		}
	})

	t.Run("accepts the %s spelling", func(t *testing.T) {
		t.Parallel()

		// Most LDAP configuration in the wild is written with %s, and
		// making people rewrite it to adopt this package would buy
		// nothing.
		tmpl, err := parseTemplate("uid=%s,ou=people,dc=example,dc=com", placeholderUsername)
		if err != nil {
			t.Fatalf("parseTemplate: %v", err)
		}

		if !tmpl.requires(placeholderUsername) {
			t.Fatal("the printf-style shorthand did not become a username placeholder")
		}
	})

	t.Run("rejects an unknown placeholder", func(t *testing.T) {
		t.Parallel()

		_, err := parseTemplate("uid={{userid}}", placeholderUsername)
		if !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("err = %v, want ErrInvalidOption", err)
		}

		if !strings.Contains(err.Error(), "userid") {
			t.Errorf("error %q does not name the offending placeholder", err)
		}
	})

	t.Run("rejects a template with no placeholder", func(t *testing.T) {
		t.Parallel()

		if _, err := parseTemplate("cn=fixed,dc=example", placeholderUsername); !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("err = %v, want ErrInvalidOption", err)
		}
	})

	t.Run("rejects an unclosed placeholder", func(t *testing.T) {
		t.Parallel()

		if _, err := parseTemplate("uid={{username", placeholderUsername); !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("err = %v, want ErrInvalidOption", err)
		}
	})

	t.Run("rejects an empty template", func(t *testing.T) {
		t.Parallel()

		if _, err := parseTemplate("", placeholderUsername); !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("err = %v, want ErrInvalidOption", err)
		}
	})
}

func TestExpandFilterEscapesValuesAndNotDNs(t *testing.T) {
	t.Parallel()

	tmpl, err := parseTemplate(
		"(&(uid={{username}})(member={{user_dn}}))",
		placeholderUsername, placeholderUserDN,
	)
	if err != nil {
		t.Fatalf("parseTemplate: %v", err)
	}

	got := tmpl.expandFilter(map[string]string{
		placeholderUsername: "a*b",
		placeholderUserDN:   "uid=alice,ou=people,dc=example,dc=com",
	})

	want := `(&(uid=a\2ab)(member=uid=alice,ou=people,dc=example,dc=com))`
	if got != want {
		t.Errorf("expandFilter = %q, want %q", got, want)
	}
}

func TestRetriableClassification(t *testing.T) {
	t.Parallel()

	retriableCases := []error{
		ldap.NewError(ldap.ErrorNetwork, errors.New("connection refused")),
		ldap.NewError(ldap.LDAPResultBusy, errors.New("busy")),
		ldap.NewError(ldap.LDAPResultUnavailable, errors.New("unavailable")),
		ErrNoServerAvailable,
	}

	for _, err := range retriableCases {
		if !retriable(err) {
			t.Errorf("retriable(%v) = false, want true", err)
		}
	}

	final := []error{
		nil,
		ErrInvalidCredentials,
		ErrEmptyPassword,
		ErrInvalidUsername,
		ErrAmbiguousUser,
		ErrClosed,
		ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("nope")),
		ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("nope")),
	}

	for _, err := range final {
		if retriable(err) {
			t.Errorf("retriable(%v) = true, want false", err)
		}
	}
}

func TestInflightCollapsesConcurrentCalls(t *testing.T) {
	t.Parallel()

	const callers = 16

	f := newInflight()

	var calls atomic.Int64

	var wg sync.WaitGroup

	shared := make(chan bool, callers)

	for range callers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			// The leader does not finish until every other caller has
			// attached, so there is no window in which a straggler can
			// arrive to find the flight already gone. No sleeping, and
			// no timing assumption.
			_, wasShared, err := f.do(t.Context(), "key", func() (Identity, error) {
				calls.Add(1)

				for f.waiting("key") < callers-1 {
					runtime.Gosched()
				}

				return &Principal{DN: "uid=alice"}, nil
			})
			if err != nil {
				t.Error(err)
			}

			shared <- wasShared
		}()
	}

	wg.Wait()
	close(shared)

	if got := calls.Load(); got != 1 {
		t.Errorf("the function ran %d times, want 1", got)
	}

	leaders := 0

	for wasShared := range shared {
		if !wasShared {
			leaders++
		}
	}

	if leaders != 1 {
		t.Errorf("%d callers thought they were the leader, want 1", leaders)
	}
}

func TestInflightGivesEveryWaiterItsOwnCopy(t *testing.T) {
	t.Parallel()

	f := newInflight()

	var wg sync.WaitGroup

	identities := make(chan Identity, 8)

	for range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			identity, _, err := f.do(t.Context(), "key", func() (Identity, error) {
				for f.waiting("key") < 7 {
					runtime.Gosched()
				}

				return &Principal{DN: "uid=alice", Groups: []string{"devs"}}, nil
			})
			if err != nil {
				t.Error(err)

				return
			}

			identities <- identity
		}()
	}

	wg.Wait()
	close(identities)

	var first *Principal

	for identity := range identities {
		p := identity.(*Principal)

		if first == nil {
			first = p

			continue
		}

		if p == first {
			t.Fatal("two callers were handed the same *Principal")
		}

		p.Groups[0] = "tampered"

		if first.Groups[0] == "tampered" {
			t.Fatal("two callers share a groups slice")
		}
	}
}

func TestInflightPropagatesTheError(t *testing.T) {
	t.Parallel()

	f := newInflight()

	sentinel := errors.New("the directory is down")

	var wg sync.WaitGroup

	for range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if _, _, err := f.do(t.Context(), "key", func() (Identity, error) {
				for f.waiting("key") < 7 {
					runtime.Gosched()
				}

				return nil, sentinel
			}); !errors.Is(err, sentinel) {
				t.Errorf("err = %v, want the sentinel", err)
			}
		}()
	}

	wg.Wait()
}

func TestInflightReleasesWaitersWhenTheLeaderPanics(t *testing.T) {
	t.Parallel()

	// A leader that panics must not leave its waiters blocked on a
	// channel nobody will close. The panic still reaches the leader's own
	// caller, which is where it belongs.
	f := newInflight()

	release := make(chan struct{})
	panicked := make(chan struct{})

	go func() {
		defer close(panicked)
		defer func() { _ = recover() }()

		_, _, _ = f.do(t.Context(), "key", func() (Identity, error) {
			close(release)

			panic("boom")
		})
	}()

	<-release

	done := make(chan struct{})

	go func() {
		defer close(done)

		// The waiter may arrive before or after the leader's deferred
		// cleanup; either way it must not block forever.
		_, _, _ = f.do(t.Context(), "key", func() (Identity, error) {
			return &Principal{DN: "uid=alice"}, nil
		})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a waiter blocked after the leader panicked")
	}

	<-panicked
}

func TestInflightForgetsFinishedCalls(t *testing.T) {
	t.Parallel()

	f := newInflight()

	for range 4 {
		if _, _, err := f.do(t.Context(), "key", func() (Identity, error) {
			return &Principal{DN: "uid=alice"}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.calls) != 0 {
		t.Errorf("%d calls are still recorded, want 0 — this is how it leaks", len(f.calls))
	}
}

// memByteStore is a minimal ByteStore for the in-package tests. It does
// not expire anything on its own: the point of the tests using it is that
// the sealed cache must not depend on a store that does.
type memByteStore struct {
	mu      sync.Mutex
	entries map[string][]byte
}

func newMemByteStore() *memByteStore {
	return &memByteStore{entries: map[string][]byte{}}
}

func (s *memByteStore) Get(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.entries[key]

	return value, ok, nil
}

func (s *memByteStore) Set(_ context.Context, key, _ string, value []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[key] = value

	return nil
}

func (s *memByteStore) InvalidateUser(context.Context, string) (int, error) { return 0, nil }
func (s *memByteStore) InvalidateAll(context.Context) (int, error)          { return 0, nil }

func (s *memByteStore) Len(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.entries), nil
}

// stepClock is a clock a test moves by hand, so that expiry is asserted
// rather than slept through.
type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *stepClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

func TestASealedEntryExpiresOnItsOwnTerms(t *testing.T) {
	t.Parallel()

	// The store's TTL is the store's business, and a store that has been
	// compromised or rolled back from a backup has no reason to honour
	// it. HMAC proves who wrote a value, not when — so the expiry lives
	// inside the seal, and is checked against this process's clock.
	//
	// Without it, an entry that was genuinely sealed when somebody was an
	// administrator keeps saying so for as long as the store serves it.
	store := newMemByteStore()
	clock := &stepClock{now: time.Unix(1_700_000_000, 0)}
	ctx := context.Background()

	sealed, err := newSealedCache(store, []byte("0123456789abcdef0123456789abcdef"), clock.Now)
	if err != nil {
		t.Fatalf("newSealedCache: %v", err)
	}

	admin := &Principal{DN: "uid=root,dc=corp", Groups: []string{"admins"}}
	if err := sealed.Set(ctx, "key", "root", admin, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	clock.advance(30 * time.Second)

	if _, hit, err := sealed.Get(ctx, "key"); !hit || err != nil {
		t.Fatalf("a live entry did not come back: hit=%v err=%v", hit, err)
	}

	clock.advance(31 * time.Second)

	// The bytes are still there and still verify. Only the clock moved.
	if _, held, _ := store.Get(ctx, "key"); !held {
		t.Fatal("the store dropped the entry, so this proves nothing")
	}

	if _, hit, err := sealed.Get(ctx, "key"); hit {
		t.Error("an expired entry was served; a store that ignores its TTL decides who somebody is")
	} else if err != nil {
		t.Errorf("an expired entry should be a plain miss, got %v", err)
	}
}

func TestTheCacheSubkeysDiffer(t *testing.T) {
	t.Parallel()

	// The property derive.go exists for, stated at the bottom: one master
	// secret, three purposes, three different keys. Sharing one made the
	// login path a signing oracle for the seal.
	master := []byte("0123456789abcdef0123456789abcdef")

	seen := map[string]string{}

	for _, domain := range []string{cacheKeyDomain, cacheSealDomain, cacheUsernameDomain} {
		subkey, err := deriveSubkey(master, domain)
		if err != nil {
			t.Fatalf("deriveSubkey(%s): %v", domain, err)
		}

		if string(subkey) == string(master) {
			t.Errorf("%s: the subkey is the master secret", domain)
		}

		if previous, clash := seen[string(subkey)]; clash {
			t.Errorf("%s and %s derive the same subkey", domain, previous)
		}

		seen[string(subkey)] = domain
	}
}
