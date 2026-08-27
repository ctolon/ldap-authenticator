package ldaptest

// The fake is load-bearing: every assertion the library's own tests make
// about escaping is really an assertion about how this filter parser reads
// what the library produced. A parser that unescaped too eagerly, or
// matched too generously, would report the attacks as failing without
// testing anything. So the parser gets its own tests.

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func mustMatch(t *testing.T, filter string, entry *Entry, want bool) {
	t.Helper()

	node, err := compileFilter(filter)
	if err != nil {
		t.Fatalf("compileFilter(%q): %v", filter, err)
	}

	if got := node.match(New(entry), entry); got != want {
		t.Errorf("filter %q against %q = %v, want %v", filter, entry.DN, got, want)
	}
}

func TestFilterEquality(t *testing.T) {
	t.Parallel()

	entry := User("uid=alice,ou=people,dc=example,dc=com", "x").With("uid", "alice")

	mustMatch(t, "(uid=alice)", entry, true)
	mustMatch(t, "(uid=ALICE)", entry, true)
	mustMatch(t, "(uid=bob)", entry, false)
	mustMatch(t, "(mail=alice)", entry, false)
}

func TestFilterPresenceAndSubstrings(t *testing.T) {
	t.Parallel()

	entry := User("uid=alice,dc=example,dc=com", "x").
		With("uid", "alice").
		With("mail", "alice@example.com")

	mustMatch(t, "(uid=*)", entry, true)
	mustMatch(t, "(nickname=*)", entry, false)
	mustMatch(t, "(mail=alice@*)", entry, true)
	mustMatch(t, "(mail=*@example.com)", entry, true)
	mustMatch(t, "(mail=*example*)", entry, true)
	mustMatch(t, "(mail=*@other.com)", entry, false)
}

func TestFilterBooleans(t *testing.T) {
	t.Parallel()

	entry := User("uid=alice,dc=example,dc=com", "x").
		With("uid", "alice").
		With("objectClass", "inetOrgPerson")

	mustMatch(t, "(&(uid=alice)(objectClass=inetOrgPerson))", entry, true)
	mustMatch(t, "(&(uid=alice)(objectClass=nope))", entry, false)
	mustMatch(t, "(|(uid=bob)(uid=alice))", entry, true)
	mustMatch(t, "(!(uid=bob))", entry, true)
	mustMatch(t, "(!(uid=alice))", entry, false)
}

func TestAnEscapedAsteriskIsNotAWildcard(t *testing.T) {
	t.Parallel()

	// This is the assertion the whole escaping story rests on. \2a is a
	// literal asterisk in a value; a bare * is structure. A parser that
	// unescaped before splitting would treat the library's escaped output
	// as a wildcard and every injection test would pass vacuously.
	entry := User("uid=alice,dc=example,dc=com", "x").With("uid", "alice")

	mustMatch(t, `(uid=\2a)`, entry, false)
	mustMatch(t, "(uid=*)", entry, true)

	literal := User("uid=star,dc=example,dc=com", "x").With("uid", "*")

	mustMatch(t, `(uid=\2a)`, literal, true)
}

func TestEscapedParenthesesStayInsideTheValue(t *testing.T) {
	t.Parallel()

	entry := User("uid=weird,dc=example,dc=com", "x").With("uid", "a(b)c")

	mustMatch(t, `(uid=a\28b\29c)`, entry, true)
	mustMatch(t, `(uid=abc)`, entry, false)
}

func TestScopes(t *testing.T) {
	t.Parallel()

	const base = "ou=people,dc=example,dc=com"

	cases := []struct {
		dn    string
		scope int
		want  bool
	}{
		{base, ldap.ScopeBaseObject, true},
		{"uid=alice," + base, ldap.ScopeBaseObject, false},
		{"uid=alice," + base, ldap.ScopeSingleLevel, true},
		{"uid=alice,ou=staff," + base, ldap.ScopeSingleLevel, false},
		{"uid=alice,ou=staff," + base, ldap.ScopeWholeSubtree, true},
		{"uid=alice,ou=other,dc=example,dc=com", ldap.ScopeWholeSubtree, false},
	}

	for _, c := range cases {
		if got := inScope(c.dn, base, c.scope); got != c.want {
			t.Errorf("inScope(%q, %q, %d) = %v, want %v", c.dn, base, c.scope, got, c.want)
		}
	}
}

func TestChainMatchWalksTransitively(t *testing.T) {
	t.Parallel()

	const (
		alice = "uid=alice,dc=example,dc=com"
		devs  = "cn=devs,dc=example,dc=com"
		staff = "cn=staff,dc=example,dc=com"
	)

	dir := New(
		User(alice, "x"),
		Group(devs).With("member", alice),
		Group(staff).With("member", devs),
	)

	node, err := compileFilter("(member:" + ChainOID + ":=" + alice + ")")
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}

	if !node.match(dir, dir.find(devs)) {
		t.Error("the direct group did not match the chain rule")
	}

	if !node.match(dir, dir.find(staff)) {
		t.Error("the nested group did not match the chain rule")
	}

	if node.match(dir, dir.find(alice)) {
		t.Error("the user matched a group membership rule")
	}
}

func TestAnEmptyPasswordBindSucceedsAsAConformingServerWould(t *testing.T) {
	t.Parallel()

	// If this ever stops being true, the library's test that it never
	// sends an empty password stops proving anything.
	dir := New(User("uid=alice,dc=example,dc=com", "s3cret"))

	conn, err := dir.Dialer().DialContext(t.Context(), "ldap://memory")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	defer func() { _ = conn.Close() }()

	if err := conn.Bind("uid=alice,dc=example,dc=com", ""); err != nil {
		t.Fatalf("an empty-password bind returned %v, want success as RFC 4511 requires", err)
	}

	if err := conn.Bind("uid=alice,dc=example,dc=com", "wrong"); err == nil {
		t.Fatal("a wrong password was accepted")
	}
}

func TestMalformedFiltersAreErrors(t *testing.T) {
	t.Parallel()

	for _, filter := range []string{"", "(", ")", "(uid)", "(&)", "(uid=alice", "uid=alice", `(uid=\zz)`} {
		if _, err := compileFilter(filter); err == nil {
			t.Errorf("compileFilter(%q) succeeded, want an error", filter)
		}
	}
}
