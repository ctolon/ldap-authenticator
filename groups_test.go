package ldapauth_test

import (
	"sort"
	"strings"
	"testing"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

func groupsOf(t *testing.T, auth *ldapauth.Client, username, password string) []string {
	t.Helper()

	p, err := auth.Authenticate(testContext(t), username, password)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	groups := append([]string(nil), p.GetGroups()...)
	sort.Strings(groups)

	return groups
}

func assertGroups(t *testing.T, got []string, want ...string) {
	t.Helper()

	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("groups = %v, want %v", got, want)
	}

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("groups = %v, want %v", got, want)
		}
	}
}

func TestGroupsAreEmptyByDefault(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory())

	assertGroups(t, groupsOf(t, auth, "alice", alicePassword))
}

func TestGroupsFromMemberOf(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir, ldapauth.WithMemberOfGroups())

	assertGroups(t, groupsOf(t, auth, "alice", alicePassword), "devs")

	// The point of this source: the memberships arrive with the user's
	// entry, so no group search happens at all.
	for _, search := range dir.Searches() {
		if search.BaseDN == groupsDN {
			t.Error("a group search was issued under the memberOf source")
		}
	}
}

func TestNestedGroupsFromMemberOf(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithNestedGroups(),
	)

	assertGroups(t, groupsOf(t, auth, "alice", alicePassword), "devs", "staff")
}

func TestGroupsFromSearch(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithGroupSearch(groupsDN, "(member={{user_dn}})"),
	)

	assertGroups(t, groupsOf(t, auth, "alice", alicePassword), "devs")
}

func TestNestedGroupsFromSearch(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithGroupSearch(groupsDN, "(member={{user_dn}})"),
		ldapauth.WithNestedGroups(),
	)

	assertGroups(t, groupsOf(t, auth, "alice", alicePassword), "devs", "staff")
}

func TestNestedGroupsStopAtTheConfiguredDepth(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithGroupSearch(groupsDN, "(member={{user_dn}})"),
		ldapauth.WithNestedGroupDepth(1),
	)

	assertGroups(t, groupsOf(t, auth, "alice", alicePassword), "devs")
}

func TestNestedGroupsSurviveACycle(t *testing.T) {
	t.Parallel()

	// devs contains staff and staff contains devs. A walk without a
	// visited set runs until the depth cap; one without either runs
	// forever.
	dir := ldaptest.New(
		ldaptest.User(aliceDN, alicePassword).
			With("uid", "alice").
			With("objectClass", "inetOrgPerson").
			With("memberOf", devsDN),
		ldaptest.User(serviceDN, servicePassword).With("objectClass", "person"),
		ldaptest.Group(devsDN).
			With("cn", "devs").
			With("objectClass", "groupOfNames").
			With("memberOf", staffDN),
		ldaptest.Group(staffDN).
			With("cn", "staff").
			With("objectClass", "groupOfNames").
			With("memberOf", devsDN),
	)

	auth := searchAuth(t, dir,
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithNestedGroupDepth(16),
	)

	assertGroups(t, groupsOf(t, auth, "alice", alicePassword), "devs", "staff")
}

func TestActiveDirectoryChainResolvesNestingInOneSearch(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := searchAuth(t, dir, ldapauth.WithActiveDirectoryGroups(groupsDN))

	assertGroups(t, groupsOf(t, auth, "alice", alicePassword), "devs", "staff")

	groupSearches := 0

	for _, search := range dir.Searches() {
		if search.BaseDN == groupsDN {
			groupSearches++
		}
	}

	if groupSearches != 1 {
		t.Errorf("group searches = %d, want 1: the server does the walking", groupSearches)
	}
}

func TestGroupDNsInsteadOfNames(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithGroupDNs(),
	)

	assertGroups(t, groupsOf(t, auth, "alice", alicePassword), devsDN)
}

func TestGroupMembershipHelpers(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithNestedGroups(),
	)

	p, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if !p.InGroup("DEVS") {
		t.Error("InGroup is case-sensitive; directories are not")
	}

	if !p.InAnyGroup("nope", "staff") {
		t.Error("InAnyGroup missed a group the principal is in")
	}

	if p.InAnyGroup() {
		t.Error("InAnyGroup with no names reported true, which would open a door")
	}

	if !p.InAllGroups("devs", "staff") {
		t.Error("InAllGroups missed a group the principal is in")
	}

	if p.InAllGroups("devs", "nope") {
		t.Error("InAllGroups reported true for a group the principal is not in")
	}

	if !p.InAllGroups() {
		t.Error("InAllGroups with no names reported false, which would reject everybody")
	}
}

func TestGroupsAreNotSharedBetweenPrincipals(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(), ldapauth.WithMemberOfGroups())

	first, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	principal, ok := ldapauth.AsPrincipal(first)
	if !ok {
		t.Fatalf("Authenticate returned %T, want the default *Principal", first)
	}

	principal.Groups[0] = "tampered"

	second, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if second.GetGroups()[0] == "tampered" {
		t.Fatal("editing one principal's groups changed the next one's")
	}
}

// A username-derived DN reaching a group filter unescaped is an
// authorisation bypass, and it is the one this package got wrong before
// v1.0: under a direct bind the DN is built from the username, so a
// username containing an asterisk produced `(member=uid=x*,ou=people,...)`
// and turned a membership test into a prefix match.
func TestAUsernameCannotWidenAGroupFilter(t *testing.T) {
	t.Parallel()

	const hostileDN = "uid=x*," + peopleDN

	dir := ldaptest.New(
		// An entry whose RDN value carries filter metacharacters — what
		// somebody who controls their own account name would have.
		ldaptest.User(hostileDN, "known-password").
			With("uid", "x*").
			With("objectClass", "inetOrgPerson"),

		ldaptest.User(serviceDN, servicePassword).With("objectClass", "person"),

		// A group they are emphatically not in.
		ldaptest.Group("cn=admins,"+groupsDN).
			With("cn", "admins").
			With("objectClass", "groupOfNames").
			With("member", "uid=xander,"+peopleDN),
	)

	auth := newAuthenticator(t, dir,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithGroupSearch(groupsDN, "(&(objectClass=groupOfNames)(member={{user_dn}}))"),
	)

	identity, err := auth.Authenticate(testContext(t), "x*", "known-password")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if groups := identity.GetGroups(); len(groups) != 0 {
		t.Fatalf("groups = %v, want none: the username widened the group filter", groups)
	}

	for _, filter := range dir.Filters() {
		if strings.Contains(filter, "x*") {
			t.Errorf("filter %q carries an unescaped asterisk from the username", filter)
		}
	}
}

// The other half of the same fix: escaping a DN for a filter must not stop
// it matching the entry it names. It does not, because ldap.EscapeFilter
// leaves commas, equals signs and spaces alone.
func TestAnEscapedDNStillMatchesItsEntry(t *testing.T) {
	t.Parallel()

	// A DN with a comma, an equals sign and a space in its value — every
	// character somebody might expect filter escaping to mangle.
	const awkwardDN = `cn=Doe\, Jane (contractor),` + peopleDN

	dir := ldaptest.New(
		ldaptest.User(awkwardDN, "jane-password").
			With("uid", "jane").
			With("cn", "Doe, Jane (contractor)").
			With("objectClass", "inetOrgPerson"),

		ldaptest.User(serviceDN, servicePassword).With("objectClass", "person"),

		ldaptest.Group("cn=contractors,"+groupsDN).
			With("cn", "contractors").
			With("objectClass", "groupOfNames").
			With("member", awkwardDN),
	)

	auth := newAuthenticator(t, dir,
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(serviceDN, servicePassword),
		ldapauth.WithGroupSearch(groupsDN, "(&(objectClass=groupOfNames)(member={{user_dn}}))"),
	)

	identity, err := auth.Authenticate(testContext(t), "jane", "jane-password")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if !identity.InGroup("contractors") {
		t.Fatalf("groups = %v, want contractors: escaping the DN broke the match", identity.GetGroups())
	}
}

// Nested resolution re-runs the group filter with each group's DN, so a
// group whose own name carries metacharacters must not widen it either.
func TestANestedGroupDNCannotWidenTheFilter(t *testing.T) {
	t.Parallel()

	dir := ldaptest.New(
		ldaptest.User(aliceDN, alicePassword).
			With("uid", "alice").With("objectClass", "inetOrgPerson"),

		ldaptest.User(serviceDN, servicePassword).With("objectClass", "person"),

		ldaptest.Group("cn=team*,"+groupsDN).
			With("cn", "team*").
			With("objectClass", "groupOfNames").
			With("member", aliceDN),

		// Reachable only if the asterisk above survives into the filter.
		ldaptest.Group("cn=secrets,"+groupsDN).
			With("cn", "secrets").
			With("objectClass", "groupOfNames").
			With("member", "cn=teams-elsewhere,"+groupsDN),
	)

	auth := newAuthenticator(t, dir,
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(serviceDN, servicePassword),
		ldapauth.WithGroupSearch(groupsDN, "(&(objectClass=groupOfNames)(member={{user_dn}}))"),
		ldapauth.WithNestedGroups(),
	)

	identity, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if identity.InGroup("secrets") {
		t.Fatalf("groups = %v, want secrets excluded: a group DN widened the filter", identity.GetGroups())
	}
}
