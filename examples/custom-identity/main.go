// Command custom-identity replaces the identity this package produces with
// the application's own user type.
//
//	go run ./examples/custom-identity
//
// Authenticate returns an ldapauth.Identity, and *ldapauth.Principal is the
// implementation the package ships. When your application already has a
// user type — with a tenant on it, a role from a database, a feature flag —
// WithPrincipalMapper lets the authenticator produce that instead, and
// everything downstream keeps working because it depends on the interface.
//
// If all you need is somewhere to hang extra data, Principal.Extra is
// already there and needs no new type. This example shows the other case:
// a type of your own, with its own methods and its own JSON shape.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const (
	peopleDN = "ou=people,dc=example,dc=com"
	groupsDN = "ou=groups,dc=example,dc=com"
)

// User is this application's notion of a person. It knows about tenants
// and roles, which the directory does not, and it marshals the way the
// application's API expects.
type User struct {
	// DN, Login, Name and Email come from the directory.
	DN    string `json:"dn"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`

	// Tenant and Roles are this application's vocabulary, derived from
	// the directory's in the mapper below.
	Tenant string   `json:"tenant"`
	Roles  []string `json:"roles"`

	// ReadOnly is a decision the directory has no opinion about.
	ReadOnly bool `json:"read_only"`
}

// User implements ldapauth.Identity. The assertion is here rather than in a
// test so that it is checked by every build.
var _ ldapauth.Identity = (*User)(nil)

// GetDN returns the distinguished name that was authenticated.
func (u *User) GetDN() string { return u.DN }

// GetUsername returns the login name.
func (u *User) GetUsername() string { return u.Login }

// GetDisplayName returns the human-readable name.
func (u *User) GetDisplayName() string { return u.Name }

// GetEmail returns the email address.
func (u *User) GetEmail() string { return u.Email }

// GetGroups returns the roles, which is what this application calls groups.
func (u *User) GetGroups() []string { return slices.Clone(u.Roles) }

// GetAttribute exposes the fields the directory did not provide, so that
// generic code can read them without knowing about this type.
func (u *User) GetAttribute(name string) string {
	if strings.EqualFold(name, "tenant") {
		return u.Tenant
	}

	return ""
}

// GetAttributeValues returns GetAttribute as a slice.
func (u *User) GetAttributeValues(name string) []string {
	if value := u.GetAttribute(name); value != "" {
		return []string{value}
	}

	return nil
}

// InGroup reports role membership, case-insensitively as a directory would.
func (u *User) InGroup(name string) bool {
	return slices.ContainsFunc(u.Roles, func(role string) bool {
		return strings.EqualFold(role, name)
	})
}

// InAnyGroup reports membership of at least one role. With no names it is
// false: "in any of nothing" is not membership.
func (u *User) InAnyGroup(names ...string) bool {
	return slices.ContainsFunc(names, u.InGroup)
}

// InAllGroups reports membership of every role. With no names it is true.
func (u *User) InAllGroups(names ...string) bool {
	for _, name := range names {
		if !u.InGroup(name) {
			return false
		}
	}

	return true
}

// Clone returns a deep copy.
//
// This is the method worth thinking about. The cache stores one Identity
// and hands out copies; a type that shared a slice between clones would let
// one caller's edit become every later caller's.
func (u *User) Clone() ldapauth.Identity {
	copied := *u
	copied.Roles = slices.Clone(u.Roles)

	return &copied
}

func main() {
	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(directory().Dialer()),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),

		// The mapper reads whatever the search fetched, so the
		// attributes it wants have to be asked for like any others.
		ldapauth.WithAttributes("cn", "mail", "o", "memberOf"),
		ldapauth.WithMemberOfGroups(),

		ldapauth.WithPrincipalMapper(ldapauth.PrincipalMapperFunc(toUser)),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}

	defer func() { _ = auth.Close() }()

	identity, err := auth.Authenticate(context.Background(), "alice", "s3cret")
	if err != nil {
		fmt.Fprintln(os.Stderr, "authentication:", err)
		os.Exit(1)
	}

	// Downstream code takes the interface and never needs to know.
	describe(identity)

	// Code that owns the type can assert for it.
	if user, ok := identity.(*User); ok {
		encoded, _ := json.MarshalIndent(user, "", "  ")
		fmt.Println(string(encoded))
	}
}

// toUser maps a completed authentication onto the application's own type.
func toUser(m ldapauth.Mapping) (ldapauth.Identity, error) {
	user := &User{
		DN:    m.DN,
		Login: m.Username,
		Roles: rolesFor(m.Groups),
	}

	if m.Entry != nil {
		user.Name = m.Entry.GetAttributeValue("cn")
		user.Email = m.Entry.GetAttributeValue("mail")
		user.Tenant = m.Entry.GetAttributeValue("o")
	}

	// Something the directory has no opinion about.
	user.ReadOnly = !user.InGroup("admin")

	return user, nil
}

// rolesFor is where an application's own vocabulary meets the directory's.
func rolesFor(groups []string) []string {
	mapping := map[string]string{
		"developers": "developer",
		"ops":        "admin",
	}

	roles := make([]string, 0, len(groups))

	for _, group := range groups {
		if role, ok := mapping[strings.ToLower(group)]; ok {
			roles = append(roles, role)
		}
	}

	return roles
}

// describe reads an identity through the interface alone.
func describe(identity ldapauth.Identity) {
	fmt.Printf("%s (%s) in %v, tenant %q, admin=%v\n\n",
		identity.GetDisplayName(),
		identity.GetEmail(),
		identity.GetGroups(),
		identity.GetAttribute("tenant"),
		identity.InGroup("admin"),
	)
}

func directory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User("uid=alice,"+peopleDN, "s3cret").
			With("uid", "alice").
			With("cn", "Alice Example").
			With("mail", "alice@example.com").
			With("o", "acme").
			With("objectClass", "inetOrgPerson").
			With("memberOf", "cn=developers,"+groupsDN).
			With("memberOf", "cn=ops,"+groupsDN),

		ldaptest.Group("cn=developers,"+groupsDN).With("cn", "developers"),
		ldaptest.Group("cn=ops,"+groupsDN).With("cn", "ops"),
	)
}
