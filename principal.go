package ldapauth

import (
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Identity is what an authentication produced: whoever the directory says
// the caller is.
//
// [Client.Authenticate] and [Client.Lookup] return one of these rather than a concrete
// type, so that a deployment whose notion of a user is richer than this
// package's can supply its own — see [WithPrincipalMapper]. [Principal] is
// the implementation this package ships, and is what you get unless you
// ask for something else; most programs will never name this interface at
// all.
//
// The accessors are spelled Get* because [Principal] carries the same
// information as exported fields, and a field and a method cannot share a
// name. It is the spelling go-ldap itself uses for [ldap.Entry].
//
// An implementation must be safe for concurrent reads, and Clone must
// return a value that shares nothing mutable with the original: the cache
// stores one Identity and hands out copies, and a caller who edits what
// they were given must not be able to edit what the next caller gets.
type Identity interface {
	// GetDN returns the distinguished name of the entry that was
	// authenticated.
	GetDN() string

	// GetUsername returns the username, as supplied or as read from the
	// attribute named by WithUsernameAttribute.
	GetUsername() string

	// GetDisplayName returns a human-readable name, or the empty string.
	GetDisplayName() string

	// GetEmail returns an email address, or the empty string.
	GetEmail() string

	// GetGroups returns the resolved group names, or DNs under
	// WithGroupDNs. The slice belongs to the caller.
	GetGroups() []string

	// GetAttribute returns the first value of an attribute, or the empty
	// string.
	GetAttribute(name string) string

	// GetAttributeValues returns every value of an attribute, or nil.
	GetAttributeValues(name string) []string

	// InGroup reports membership, compared case-insensitively.
	InGroup(name string) bool

	// InAnyGroup reports membership of at least one of the named groups.
	// With no names it must report false.
	InAnyGroup(names ...string) bool

	// InAllGroups reports membership of every named group. With no names
	// it must report true.
	InAllGroups(names ...string) bool

	// Clone returns a deep copy.
	Clone() Identity
}

// Principal is the [Identity] this package produces by default.
//
// It is a plain struct with exported fields, so it can be constructed in a
// test or a fake without going through the directory, and it satisfies
// [Identity], so it can be returned from a custom [PrincipalMapper] that
// only wants to adjust the mapping rather than replace the type.
//
// A Principal is owned by whoever received it: the authenticator keeps no
// reference, and one served from cache is a copy. Mutate it freely.
type Principal struct {
	// DN is the distinguished name of the entry that was authenticated.
	// Under a direct bind with no lookup it is the expanded bind template;
	// otherwise it is the DN the directory returned.
	DN string

	// Username is the username as supplied to Authenticate, unless
	// WithUsernameAttribute named an attribute to read it from.
	Username string

	// DisplayName is the value of the attribute named by
	// WithDisplayNameAttribute, or empty.
	DisplayName string

	// Email is the value of the attribute named by WithEmailAttribute, or
	// empty.
	Email string

	// Groups holds the resolved group names, or group DNs under
	// WithGroupDNs. It is empty when group resolution is disabled, which
	// is the default. Order follows the directory and is not meaningful.
	Groups []string

	// Attributes holds every attribute the search asked for, exactly as
	// the directory returned it. It is nil when nothing was fetched.
	Attributes map[string][]string

	// Extra is untouched by this package. It is somewhere for a custom
	// PrincipalMapper to put whatever it looked up alongside the
	// directory entry — a tenant, a role from a database, a feature flag —
	// without having to implement Identity from scratch.
	//
	// Clone copies the field, not what it points at. An Extra that is
	// mutable is shared between clones, so put something immutable in it.
	Extra any
}

// GetDN returns [Principal.DN].
func (p *Principal) GetDN() string { return p.DN }

// GetUsername returns [Principal.Username].
func (p *Principal) GetUsername() string { return p.Username }

// GetDisplayName returns [Principal.DisplayName].
func (p *Principal) GetDisplayName() string { return p.DisplayName }

// GetEmail returns [Principal.Email].
func (p *Principal) GetEmail() string { return p.Email }

// GetGroups returns a copy, so that a caller ranging over it cannot be
// surprised by an Identity implementation that shares its slice.
func (p *Principal) GetGroups() []string { return slices.Clone(p.Groups) }

// InGroup reports whether the principal is in the named group.
//
// The comparison is case-insensitive. LDAP directories match group names
// and DNs case-insensitively, so a case-sensitive check here would be a
// check that passes in testing and fails against the directory that
// capitalises differently.
func (p *Principal) InGroup(name string) bool {
	return slices.ContainsFunc(p.Groups, func(g string) bool {
		return strings.EqualFold(g, name)
	})
}

// InAnyGroup reports whether the principal is in at least one of the named
// groups. An empty list reports false: "in any of nothing" is not
// membership, and returning true would turn an unset configuration into an
// open door.
func (p *Principal) InAnyGroup(names ...string) bool {
	return slices.ContainsFunc(names, p.InGroup)
}

// InAllGroups reports whether the principal is in every named group. An
// empty list reports true, which is the vacuous reading and the useful one:
// "no group is required" should not reject anybody.
func (p *Principal) InAllGroups(names ...string) bool {
	for _, name := range names {
		if !p.InGroup(name) {
			return false
		}
	}

	return true
}

// GetAttribute returns the first value of the named attribute, or the
// empty string. The lookup is case-insensitive, because directories are
// inconsistent about the case of attribute names in results.
func (p *Principal) GetAttribute(name string) string {
	values := p.GetAttributeValues(name)
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

// GetAttributeValues returns every value of the named attribute, or nil.
func (p *Principal) GetAttributeValues(name string) []string {
	if p.Attributes == nil {
		return nil
	}

	if values, ok := p.Attributes[name]; ok {
		return slices.Clone(values)
	}

	for key, values := range p.Attributes {
		if strings.EqualFold(key, name) {
			return slices.Clone(values)
		}
	}

	return nil
}

// Clone returns a deep copy. The cache stores one Principal and hands out
// another, so that a caller who edits what they were given cannot edit
// what the next caller will be given.
func (p *Principal) Clone() Identity {
	return p.clone()
}

func (p *Principal) clone() *Principal {
	if p == nil {
		return nil
	}

	out := *p
	out.Groups = slices.Clone(p.Groups)

	if p.Attributes != nil {
		out.Attributes = make(map[string][]string, len(p.Attributes))

		for key, values := range p.Attributes {
			out.Attributes[key] = slices.Clone(values)
		}
	}

	return &out
}

// AsPrincipal recovers the concrete [Principal] behind an [Identity], for
// callers who have not replaced the mapper and would rather read fields
// than call accessors.
//
//	if p, ok := ldapauth.AsPrincipal(identity); ok {
//	    log.Println(p.DN, p.Attributes)
//	}
func AsPrincipal(identity Identity) (*Principal, bool) {
	p, ok := identity.(*Principal)

	return p, ok
}

// Mapping is what a [PrincipalMapper] is given: everything the
// authentication established, before it becomes an [Identity].
type Mapping struct {
	// Username is the username as supplied to Authenticate.
	Username string

	// DN is the distinguished name that was authenticated.
	DN string

	// Entry is the directory entry, or nil when the configuration read
	// none. The mapper must not retain it.
	Entry *ldap.Entry

	// Groups are the resolved groups, already expanded and labelled.
	Groups []string
}

// A PrincipalMapper turns a completed authentication into an [Identity].
//
// Replacing it is the way to make this package produce your application's
// own user type, or to enrich the one it ships with information from
// somewhere else. The default reads the attributes named by
// WithEmailAttribute and friends into a [Principal].
//
// It runs on the goroutine handling the request, inside the caller's
// context and inside the retry loop, so it should be quick and it must not
// have side effects that would be wrong to repeat. An error it returns
// fails the authentication.
type PrincipalMapper interface {
	// MapPrincipal turns a completed authentication into an Identity.
	// Returning a nil Identity with a nil error is an error in itself:
	// there is no such thing as a successful authentication with nobody
	// behind it.
	MapPrincipal(mapping Mapping) (Identity, error)
}

// PrincipalMapperFunc adapts a function to [PrincipalMapper].
type PrincipalMapperFunc func(mapping Mapping) (Identity, error)

// MapPrincipal calls f.
func (f PrincipalMapperFunc) MapPrincipal(mapping Mapping) (Identity, error) {
	return f(mapping)
}

// defaultMapper maps a directory entry onto a Principal according to the
// configured attribute names.
type defaultMapper struct{ cfg *config }

func (m defaultMapper) MapPrincipal(mapping Mapping) (Identity, error) {
	c := m.cfg

	p := &Principal{
		DN:       mapping.DN,
		Username: mapping.Username,
		Groups:   mapping.Groups,
	}

	entry := mapping.Entry
	if entry == nil {
		return p, nil
	}

	if entry.DN != "" {
		p.DN = entry.DN
	}

	if len(entry.Attributes) > 0 {
		p.Attributes = make(map[string][]string, len(entry.Attributes))
	}

	for _, attr := range entry.Attributes {
		p.Attributes[attr.Name] = slices.Clone(attr.Values)
	}

	if c.usernameAttribute != "" {
		if v := p.GetAttribute(c.usernameAttribute); v != "" {
			p.Username = v
		}
	}

	if c.displayNameAttribute != "" {
		p.DisplayName = p.GetAttribute(c.displayNameAttribute)
	}

	if c.emailAttribute != "" {
		p.Email = p.GetAttribute(c.emailAttribute)
	}

	return p, nil
}
