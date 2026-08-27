package ldapauth_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

func TestPrincipalAccessorsHandOutCopies(t *testing.T) {
	t.Parallel()

	// An Identity implementation that shared its slices would let one
	// caller's range loop be rewritten by another's append.
	p := &ldapauth.Principal{
		DN:         "uid=alice,ou=people,dc=example,dc=com",
		Groups:     []string{"devs"},
		Attributes: map[string][]string{"mail": {"alice@example.com"}},
	}

	groups := p.GetGroups()
	groups[0] = "tampered"

	if p.GetGroups()[0] != "devs" {
		t.Error("GetGroups handed out the backing slice")
	}

	values := p.GetAttributeValues("mail")
	values[0] = "tampered"

	if p.GetAttribute("mail") != "alice@example.com" {
		t.Error("GetAttributeValues handed out the backing slice")
	}
}

func TestPrincipalCloneSharesNothingMutable(t *testing.T) {
	t.Parallel()

	original := &ldapauth.Principal{
		DN:         "uid=alice",
		Groups:     []string{"devs"},
		Attributes: map[string][]string{"mail": {"alice@example.com"}},
	}

	clone, ok := ldapauth.AsPrincipal(original.Clone())
	if !ok {
		t.Fatal("Clone did not return a *Principal")
	}

	clone.DN = "cn=tampered"
	clone.Groups[0] = "tampered"
	clone.Attributes["mail"][0] = "tampered"
	clone.Attributes["new"] = []string{"tampered"}

	if original.DN != "uid=alice" || original.Groups[0] != "devs" {
		t.Error("editing a clone changed the original")
	}

	if original.GetAttribute("mail") != "alice@example.com" {
		t.Error("editing a clone's attributes changed the original's")
	}

	if _, added := original.Attributes["new"]; added {
		t.Error("adding an attribute to a clone added it to the original")
	}
}

func TestPrincipalCloneOfNilIsNil(t *testing.T) {
	t.Parallel()

	var p *ldapauth.Principal

	if clone, _ := ldapauth.AsPrincipal(p.Clone()); clone != nil {
		t.Errorf("cloning a nil principal produced %v", clone)
	}
}

func TestAsPrincipalReportsAForeignIdentity(t *testing.T) {
	t.Parallel()

	if _, ok := ldapauth.AsPrincipal(customIdentity{}); ok {
		t.Error("AsPrincipal claimed a foreign Identity was a *Principal")
	}
}

// customIdentity is what a deployment with its own user type would supply
// from a PrincipalMapper.
type customIdentity struct {
	dn     string
	name   string
	groups []string
	tenant string
}

func (c customIdentity) GetDN() string          { return c.dn }
func (c customIdentity) GetUsername() string    { return c.name }
func (c customIdentity) GetDisplayName() string { return c.name }
func (c customIdentity) GetEmail() string       { return "" }
func (c customIdentity) GetGroups() []string    { return slices.Clone(c.groups) }

func (c customIdentity) GetAttribute(name string) string {
	if name == "tenant" {
		return c.tenant
	}

	return ""
}

func (c customIdentity) GetAttributeValues(name string) []string {
	if v := c.GetAttribute(name); v != "" {
		return []string{v}
	}

	return nil
}

func (c customIdentity) InGroup(name string) bool {
	return slices.ContainsFunc(c.groups, func(g string) bool { return strings.EqualFold(g, name) })
}

func (c customIdentity) InAnyGroup(names ...string) bool {
	return slices.ContainsFunc(names, c.InGroup)
}

func (c customIdentity) InAllGroups(names ...string) bool {
	for _, name := range names {
		if !c.InGroup(name) {
			return false
		}
	}

	return true
}

// The value is immutable, so a clone can be itself.
func (c customIdentity) Clone() ldapauth.Identity { return c }

func TestCustomPrincipalMapper(t *testing.T) {
	t.Parallel()

	var seen ldapauth.Mapping

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithPrincipalMapper(ldapauth.PrincipalMapperFunc(
			func(m ldapauth.Mapping) (ldapauth.Identity, error) {
				seen = m

				return customIdentity{
					dn:     m.DN,
					name:   m.Username,
					groups: m.Groups,
					tenant: "acme",
				}, nil
			},
		)),
	)

	identity, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if _, ok := ldapauth.AsPrincipal(identity); ok {
		t.Fatal("the custom mapper's identity was replaced by a *Principal")
	}

	if identity.GetAttribute("tenant") != "acme" {
		t.Errorf("tenant = %q, want acme", identity.GetAttribute("tenant"))
	}

	if !identity.InGroup("devs") {
		t.Errorf("groups = %v, want devs", identity.GetGroups())
	}

	// The mapper is handed everything the authentication established.
	if seen.DN != aliceDN {
		t.Errorf("mapping DN = %q, want %q", seen.DN, aliceDN)
	}

	if seen.Entry == nil || seen.Entry.GetAttributeValue("mail") != "alice@example.com" {
		t.Error("the mapper was not given the directory entry")
	}
}

func TestAPrincipalMapperErrorFailsTheAuthentication(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("the entitlements service is down")

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithoutRetry(),
		ldapauth.WithPrincipalMapper(ldapauth.PrincipalMapperFunc(
			func(ldapauth.Mapping) (ldapauth.Identity, error) { return nil, sentinel },
		)),
	)

	_, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the mapper's error", err)
	}
}

func TestAPrincipalMapperReturningNothingIsAnError(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithoutRetry(),
		ldapauth.WithPrincipalMapper(ldapauth.PrincipalMapperFunc(
			func(ldapauth.Mapping) (ldapauth.Identity, error) { return nil, nil },
		)),
	)

	_, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if !errors.Is(err, ldapauth.ErrInvalidOption) {
		t.Fatalf("err = %v, want ErrInvalidOption", err)
	}
}

func TestCustomGroupResolver(t *testing.T) {
	t.Parallel()

	var seen ldapauth.GroupRequest

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithGroupResolver(ldapauth.GroupResolverFunc(
			func(_ context.Context, request ldapauth.GroupRequest) ([]string, error) {
				seen = request

				return []string{"from-elsewhere"}, nil
			},
		)),
	)

	identity, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if !identity.InGroup("from-elsewhere") {
		t.Errorf("groups = %v, want the resolver's answer", identity.GetGroups())
	}

	if seen.DN != aliceDN || seen.Username != "alice" {
		t.Errorf("the resolver was given %+v", seen)
	}

	if seen.Search == nil {
		t.Error("the resolver was given no Searcher")
	}
}

func TestACustomGroupResolverCanStillSearch(t *testing.T) {
	t.Parallel()

	// The Searcher is the point of the interface: a resolver that mostly
	// wants its own logic can still ask the directory, on the
	// authenticator's connection and with its identity.
	auth := searchAuth(t, newDirectory(),
		ldapauth.WithGroupResolver(ldapauth.GroupResolverFunc(
			func(ctx context.Context, request ldapauth.GroupRequest) ([]string, error) {
				result, err := request.Search.Search(ctx, ldap.NewSearchRequest(
					groupsDN,
					ldap.ScopeWholeSubtree,
					ldap.NeverDerefAliases,
					0, 0, false,
					"(member="+request.DN+")",
					[]string{"cn"},
					nil,
				))
				if err != nil {
					return nil, err
				}

				groups := make([]string, 0, len(result.Entries))

				for _, entry := range result.Entries {
					groups = append(groups, "ldap:"+entry.GetAttributeValue("cn"))
				}

				return groups, nil
			},
		)),
	)

	identity, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if !identity.InGroup("ldap:devs") {
		t.Errorf("groups = %v, want ldap:devs", identity.GetGroups())
	}
}

func TestAGroupResolverErrorFailsTheAuthentication(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("the group service is down")

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithoutRetry(),
		ldapauth.WithGroupResolver(ldapauth.GroupResolverFunc(
			func(context.Context, ldapauth.GroupRequest) ([]string, error) { return nil, sentinel },
		)),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the resolver's error", err)
	}
}

func TestNoGroupsResolvesNothing(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithGroupResolver(ldapauth.NoGroups{}),
	)

	identity, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if len(identity.GetGroups()) != 0 {
		t.Errorf("groups = %v, want none", identity.GetGroups())
	}
}

func TestACustomResolverSearchesAsTheServiceAccount(t *testing.T) {
	t.Parallel()

	// A replaced resolver is handed a Searcher, and it must be the
	// service account's — otherwise the search silently runs with the
	// user's own read permissions and comes back empty on a directory
	// that hides the group tree.
	dir := newDirectory()

	auth := newAuthenticator(t, dir,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithServiceAccount(serviceDN, servicePassword),
		ldapauth.WithGroupResolver(ldapauth.GroupResolverFunc(
			func(ctx context.Context, request ldapauth.GroupRequest) ([]string, error) {
				_, err := request.Search.Search(ctx, ldap.NewSearchRequest(
					groupsDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
					0, 0, false, "(member="+request.DN+")", []string{"cn"}, nil,
				))

				return nil, err
			},
		)),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	serviceBinds := 0

	for _, bind := range dir.Binds() {
		if bind.DN == serviceDN {
			serviceBinds++
		}
	}

	if serviceBinds == 0 {
		t.Error("the resolver's search did not run as the service account")
	}
}
