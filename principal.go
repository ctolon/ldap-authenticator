package ldapauth

import (
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Principal is who the directory says the caller is.
//
// A Principal is produced by a successful Authenticate or by Lookup, and
// is owned by whoever received it: the authenticator keeps no reference,
// and a Principal served from cache is a copy. Mutate it freely.
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
}

// InGroup reports whether the principal is in the named group.
//
// The comparison is case-insensitive. LDAP directories match group names
// and DNs case-insensitively, so a case-sensitive check here would be a
// check that passes in testing and fails against the directory that
// capitalises differently.
func (p *Principal) InGroup(name string) bool {
	for _, g := range p.Groups {
		if strings.EqualFold(g, name) {
			return true
		}
	}

	return false
}

// InAnyGroup reports whether the principal is in at least one of the named
// groups. An empty list reports false: "in any of nothing" is not
// membership, and returning true would turn an unset configuration into an
// open door.
func (p *Principal) InAnyGroup(names ...string) bool {
	for _, name := range names {
		if p.InGroup(name) {
			return true
		}
	}

	return false
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

// Attribute returns the first value of the named attribute, or the empty
// string. The lookup is case-insensitive, because directories are
// inconsistent about the case of attribute names in results.
func (p *Principal) Attribute(name string) string {
	values := p.AttributeValues(name)
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

// AttributeValues returns every value of the named attribute, or nil.
func (p *Principal) AttributeValues(name string) []string {
	if p.Attributes == nil {
		return nil
	}

	if values, ok := p.Attributes[name]; ok {
		return values
	}

	for key, values := range p.Attributes {
		if strings.EqualFold(key, name) {
			return values
		}
	}

	return nil
}

// clone deep-copies the principal. The cache stores one of these and hands
// out another, so that a caller who edits what they were given cannot edit
// what the next caller will be given.
func (p *Principal) clone() *Principal {
	if p == nil {
		return nil
	}

	out := *p

	if p.Groups != nil {
		out.Groups = make([]string, len(p.Groups))
		copy(out.Groups, p.Groups)
	}

	if p.Attributes != nil {
		out.Attributes = make(map[string][]string, len(p.Attributes))

		for key, values := range p.Attributes {
			copied := make([]string, len(values))
			copy(copied, values)
			out.Attributes[key] = copied
		}
	}

	return &out
}

// newPrincipal maps a directory entry onto a Principal according to the
// configured attribute names. entry may be nil, which is the direct-bind
// case where nothing was looked up.
func (c *config) newPrincipal(username, dn string, entry *ldap.Entry) *Principal {
	p := &Principal{
		DN:       dn,
		Username: username,
	}

	if entry == nil {
		return p
	}

	if entry.DN != "" {
		p.DN = entry.DN
	}

	if len(entry.Attributes) > 0 {
		p.Attributes = make(map[string][]string, len(entry.Attributes))
	}

	for _, attr := range entry.Attributes {
		values := make([]string, len(attr.Values))
		copy(values, attr.Values)
		p.Attributes[attr.Name] = values
	}

	if c.usernameAttribute != "" {
		if v := p.Attribute(c.usernameAttribute); v != "" {
			p.Username = v
		}
	}

	if c.displayNameAttribute != "" {
		p.DisplayName = p.Attribute(c.displayNameAttribute)
	}

	if c.emailAttribute != "" {
		p.Email = p.Attribute(c.emailAttribute)
	}

	return p
}
