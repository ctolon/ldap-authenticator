package ldapauth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

// The end-to-end property tests. The targets in fuzz_test.go check the
// escapers in isolation; these check the thing that actually matters —
// that no username, however constructed, authenticates as somebody it is
// not — through the whole package and against a directory that parses
// filters and DNs for real.

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

	f.Fuzz(func(t *testing.T, username, password string) {
		dir := newDirectory()

		auth := searchAuth(t, dir, ldapauth.WithoutRetry())

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

	f.Fuzz(func(t *testing.T, username, password string) {
		dir := newDirectory().Add(
			// The entry a DN injection would be trying to reach.
			ldaptest.User("uid=root,ou=admins,"+baseDN, "root-password").With("uid", "root"),
		)

		auth := directAuth(t, dir, ldapauth.WithoutRetry())

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

	f.Fuzz(func(t *testing.T, username string) {
		dir := newDirectory()

		auth := searchAuth(t, dir, ldapauth.WithoutRetry())

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
