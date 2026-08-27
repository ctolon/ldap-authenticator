package ldapauth_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

// The end-to-end property tests. The targets in fuzz_test.go check the
// escapers in isolation; these check the thing that actually matters —
// that no username, however constructed, authenticates as somebody it is
// not — through the whole package and against a directory that parses
// filters and DNs for real.
//
// Each builds its fixture once, in the F, rather than once per execution.
// Building a whole authenticator four million times is not what these are
// testing, and at a hundred thousand executions a second across
// twenty-eight workers it was enough allocation to leave the coordinator
// unable to shut the workers down inside its own deadline — a gate that
// failed with "context deadline exceeded" and nothing to do with the
// property under test. Reusing one authenticator across executions is also
// closer to how the package is actually used.

var authFuzzSeeds = []struct{ username, password string }{
	{"alice", alicePassword},
	{"alice", "wrong"},
	{"", ""},
	{"alice", ""},
	{"*", alicePassword},
	{"*)(uid=*", alicePassword},
	{"alice)(|(uid=*", "x"},
	{"admin,ou=admins,dc=example,dc=com", "x"},
	{`alice\`, "x"},
	{"ALICE", alicePassword},
	{"alice ", alicePassword},
	{" alice", alicePassword},
	{"al\x00ice", alicePassword},
	{"héllo", "x"},
	{"uid=alice,ou=people,dc=example,dc=com", alicePassword},
}

// FuzzSearchThenBindAdmitsOnlyTheRealUser asserts the property the whole
// package exists for: under the search-then-bind strategy, exactly one
// (username, password) pair authenticates, and it is the real one.
func FuzzSearchThenBindAdmitsOnlyTheRealUser(f *testing.F) {
	for _, seed := range authFuzzSeeds {
		f.Add(seed.username, seed.password)
	}

	dir := newDirectory()
	auth := searchAuth(f, dir, ldapauth.WithoutRetry())

	f.Fuzz(func(t *testing.T, username, password string) {
		identity, err := auth.Authenticate(t.Context(), username, password)

		if err != nil {
			// Whatever went wrong, it must be one of the failures the
			// package documents. An error outside the set is a hole in
			// the contract even when it happens to be safe.
			if !isDocumentedFailure(err) {
				t.Fatalf("username %q produced an undocumented error: %v", username, err)
			}

			return
		}

		// A success is only legitimate for the real credential. LDAP
		// matches usernames case-insensitively, so a different spelling of
		// alice with the right password is a real success.
		if password != alicePassword || !isAliceSpelling(username) {
			t.Fatalf("username %q with password %q authenticated as %q", username, password, identity.GetDN())
		}

		if identity.GetDN() != aliceDN {
			t.Fatalf("username %q authenticated as %q, want %q", username, identity.GetDN(), aliceDN)
		}
	})
}

// FuzzDirectBindStaysInsideItsSubtree asserts that no username can make a
// direct bind name an entry outside the subtree the template points at.
func FuzzDirectBindStaysInsideItsSubtree(f *testing.F) {
	for _, seed := range authFuzzSeeds {
		f.Add(seed.username, seed.password)
	}

	dir := newDirectory().Add(
		// The entry a DN injection would be trying to reach.
		ldaptest.User("uid=root,ou=admins,"+baseDN, "root-password").With("uid", "root"),
	)

	auth := directAuth(f, dir, ldapauth.WithoutRetry())

	f.Fuzz(func(t *testing.T, username, password string) {
		dir.Reset()

		_, _ = auth.Authenticate(t.Context(), username, password)

		for _, bind := range dir.Binds() {
			parsed, err := ldap.ParseDN(bind.DN)
			if err != nil {
				t.Fatalf("username %q produced an unparseable bind DN %q", username, bind.DN)
			}

			// uid=<value>,ou=people,dc=example,dc=com — four components,
			// always, whatever the username contained.
			if len(parsed.RDNs) != 4 {
				t.Fatalf("username %q produced a bind DN with %d components: %q",
					username, len(parsed.RDNs), bind.DN)
			}

			people, err := ldap.ParseDN(peopleDN)
			if err != nil {
				t.Fatal(err)
			}

			if !people.AncestorOfFold(parsed) {
				t.Fatalf("username %q bound outside the configured subtree: %q", username, bind.DN)
			}
		}
	})
}

// FuzzUserSearchFilterStaysOneTerm asserts that whatever the username, the
// filter that goes to the directory is still the single equality test the
// template described.
func FuzzUserSearchFilterStaysOneTerm(f *testing.F) {
	for _, seed := range authFuzzSeeds {
		f.Add(seed.username)
	}

	dir := newDirectory()
	auth := searchAuth(f, dir, ldapauth.WithoutRetry())

	f.Fuzz(func(t *testing.T, username string) {
		dir.Reset()

		_, _ = auth.Authenticate(t.Context(), username, "irrelevant")

		for _, filter := range dir.Filters() {
			// The directory parsed it, so it is well formed. What matters
			// is that it has the shape the template had: one term, not
			// two, and no wildcard the template did not contain.
			if got := countUnescaped(filter, '('); got != 1 {
				t.Fatalf("username %q produced %d filter terms: %q", username, got, filter)
			}

			if countUnescaped(filter, '*') != 0 {
				t.Fatalf("username %q introduced a wildcard: %q", username, filter)
			}
		}
	})
}

// countUnescaped counts structural characters — the ones that are not part
// of a \xx escape.
func countUnescaped(filter string, want byte) int {
	n := 0

	for i := 0; i < len(filter); i++ {
		if filter[i] == '\\' {
			i += 2

			continue
		}

		if filter[i] == want {
			n++
		}
	}

	return n
}

// isAliceSpelling reports whether a username is one the directory would
// match to alice's entry. The fake matches attribute values
// case-insensitively, as a directory does.
func isAliceSpelling(username string) bool {
	return strings.EqualFold(username, "alice")
}

// isDocumentedFailure reports whether an error is one of the outcomes the
// package says it can produce.
func isDocumentedFailure(err error) bool {
	for _, sentinel := range []error{
		ldapauth.ErrInvalidCredentials,
		ldapauth.ErrEmptyUsername,
		ldapauth.ErrEmptyPassword,
		ldapauth.ErrInvalidUsername,
		ldapauth.ErrInvalidPassword,
		ldapauth.ErrAmbiguousUser,
		ldapauth.ErrUserNotFound,
		ldapauth.ErrNoServerAvailable,
		ldapauth.ErrPoolExhausted,
		ldapauth.ErrClosed,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}

	return false
}

// FuzzGroupFilterStaysOneTerm is the end-to-end form of the fix that
// v1.0 nearly shipped without: whatever the username, the *group* filter
// that reaches the directory still has the shape the template described.
//
// It is a separate target from the user-search one because it exercises a
// different splice. Under a direct bind the DN in `(member={{user_dn}})`
// is built from the username, so a username that survives into it
// unescaped widens a membership test into a prefix match — which is an
// authorisation bypass rather than a failed login.
func FuzzGroupFilterStaysOneTerm(f *testing.F) {
	for _, seed := range authFuzzSeeds {
		f.Add(seed.username)
	}

	f.Add("x*")
	f.Add("a)(objectClass=*")
	f.Add(`a\`)

	dir := newDirectory()

	auth := newAuthenticator(f, dir,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithGroupSearch(groupsDN, "(&(objectClass=groupOfNames)(member={{user_dn}}))"),
		ldapauth.WithNestedGroups(),
		ldapauth.WithoutRetry(),
	)

	f.Fuzz(func(t *testing.T, username string) {
		dir.Reset()

		_, _ = auth.Authenticate(t.Context(), username, alicePassword)

		for _, filter := range dir.Filters() {
			// The template has two terms and no wildcard. Whatever the
			// username was, that is still what went out.
			if got := countUnescaped(filter, '('); got != 3 {
				t.Fatalf("username %q produced %d filter groupings: %q", username, got, filter)
			}

			if countUnescaped(filter, '*') != 0 {
				t.Fatalf("username %q introduced a wildcard: %q", username, filter)
			}
		}
	})
}

// FuzzSealedCacheRejectsEverythingItDidNotWrite asserts the property the
// whole sealed cache rests on: nothing verifies under a key unless this
// cache sealed exactly those bytes under exactly that key.
//
// The seeds are real sealed values, so the fuzzer mutates well-formed
// input rather than noise — a valid entry with a bit flipped, a valid
// entry under a neighbouring key, a valid tag in front of a different
// payload. They are sealed under one secret and read back under another,
// which makes the invariant absolute: the cache under test wrote none of
// these bytes, so a hit of any kind is a failure and there is no
// legitimate case to carve out.
func FuzzSealedCacheRejectsEverythingItDidNotWrite(f *testing.F) {
	// Sealing inside the fuzz function would spend the budget on HMAC
	// rather than on mutation, so the seeds are built once.
	seeds := newByteStore()

	sealed, err := ldapauth.NewSealedCache(seeds, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		f.Fatalf("NewSealedCache: %v", err)
	}

	ctx := context.Background()

	for i, identity := range []ldapauth.Identity{
		nil,
		&ldapauth.Principal{DN: "uid=alice,dc=corp"},
		&ldapauth.Principal{DN: "uid=root,dc=corp", Groups: []string{"admins", "domain admins"}},
	} {
		key := fmt.Sprintf("key-%d", i)

		if err := sealed.Set(ctx, key, "alice", identity, time.Minute); err != nil {
			f.Fatalf("sealing seed %d: %v", i, err)
		}

		value, _, err := seeds.Get(ctx, key)
		if err != nil {
			f.Fatalf("reading seed %d: %v", i, err)
		}

		f.Add(key, value)
	}

	f.Add("key-0", []byte(nil))
	f.Add("", []byte(`{"v":1,"identity":{"dn":"uid=root","groups":["admins"]}}`))

	store := newByteStore()

	subject, err := ldapauth.NewSealedCache(store, []byte("fedcba9876543210fedcba9876543210"))
	if err != nil {
		f.Fatalf("NewSealedCache: %v", err)
	}

	f.Fuzz(func(t *testing.T, key string, value []byte) {
		store.put(key, value)

		// The error is deliberately ignored: a value that fails its seal
		// or its decode reports one, and the assertion is only that it
		// did not become a hit.
		identity, hit, _ := subject.Get(ctx, key)
		if hit {
			t.Fatalf("a value this cache never wrote verified under %q: identity=%v value=%x",
				key, identity, value)
		}
	})
}
