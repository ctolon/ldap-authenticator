package ldapauth_test

import (
	"sort"
	"testing"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

func groupsOf(t *testing.T, auth *ldapauth.Authenticator, username, password string) []string {
	t.Helper()

	p, err := auth.Authenticate(testContext(t), username, password)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	groups := append([]string(nil), p.Groups...)
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

	first.Groups[0] = "tampered"

	second, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if second.Groups[0] == "tampered" {
		t.Fatal("editing one principal's groups changed the next one's")
	}
}
