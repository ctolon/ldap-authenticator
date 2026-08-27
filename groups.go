package ldapauth

import (
	"context"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// resolveGroups produces the group list for an authenticated principal.
//
// Which of the three shapes runs is a configuration decision, and the
// trade-off between them is round trips against directory support:
//
//	GroupsFromMemberOf   free, needs the memberOf attribute to exist
//	GroupsFromSearch     one search, works anywhere
//	AD matching rule     one search, transitive, Active Directory only
//
// Nested expansion, where it is done client-side, is bounded twice: by the
// configured depth and by a visited set. Group graphs with cycles in them
// are not rare — a directory will happily let two groups contain each
// other — and either bound alone would be enough, which is why there are
// two.
func (a *Authenticator) resolveGroups(ctx context.Context, r *resolved, username string) ([]string, error) {
	switch a.cfg.groupSource {
	case GroupsDisabled:
		return nil, nil

	case GroupsFromMemberOf:
		return a.groupsFromMemberOf(ctx, r)

	case GroupsFromSearch:
		return a.groupsFromSearch(ctx, r, username)

	default:
		return nil, nil
	}
}

// groupsFromMemberOf reads the memberships off the user's own entry.
func (a *Authenticator) groupsFromMemberOf(ctx context.Context, r *resolved) ([]string, error) {
	if r.entry == nil {
		return nil, nil
	}

	dns := r.entry.GetAttributeValues(a.cfg.memberOfAttribute)

	if !a.cfg.nestedGroups || a.cfg.activeDirectoryChain {
		return a.namesFor(r, dns)
	}

	// Walk upwards: each group is itself an entry that may carry its own
	// memberOf. One lookup per group per level, which is why the AD
	// matching rule is worth using where it is available.
	seen := make(map[string]struct{}, len(dns)*2)
	ordered := make([]string, 0, len(dns)*2)

	frontier := dns

	for depth := 0; depth < a.cfg.nestedGroupDepth && len(frontier) > 0; depth++ {
		var next []string

		for _, dn := range frontier {
			key := strings.ToLower(dn)

			if _, dup := seen[key]; dup {
				continue
			}

			seen[key] = struct{}{}
			ordered = append(ordered, dn)

			parents, err := a.parentsOf(ctx, r, dn)
			if err != nil {
				return nil, err
			}

			next = append(next, parents...)
		}

		frontier = next
	}

	return a.namesFor(r, ordered)
}

// parentsOf reads one group's own memberOf attribute.
func (a *Authenticator) parentsOf(ctx context.Context, r *resolved, dn string) ([]string, error) {
	entry, err := a.onConn(ctx, r, func(conn Conn) (*ldap.Entry, error) {
		request := ldap.NewSearchRequest(
			dn,
			ScopeBaseObject,
			a.cfg.userDerefAliases,
			1,
			a.searchTimeLimit(),
			false,
			"(objectClass=*)",
			[]string{a.cfg.memberOfAttribute, a.cfg.groupNameAttribute},
			nil,
		)

		result, serr := a.search(conn, request)
		if serr != nil {
			return nil, serr
		}

		if len(result.Entries) == 0 {
			return nil, nil
		}

		return result.Entries[0], nil
	})
	if err != nil {
		// A group that cannot be read is a hole in the answer, not a
		// failed login. Nested expansion is best-effort by nature: the
		// directory may simply not let this identity read the group tree,
		// and refusing the authentication over it would be a worse
		// outcome than reporting the memberships that could be read.
		// Worth a warning rather than a debug line: the login succeeded
		// and the group list it carries is incomplete, which is exactly
		// the kind of failure that shows up later as a mysterious
		// authorisation denial.
		a.warn("nested group lookup failed; the group list may be incomplete",
			"group", dn, "error", err)

		return nil, nil
	}

	if entry == nil {
		return nil, nil
	}

	r.rememberGroupName(a.cfg.groupNameAttribute, entry)

	return entry.GetAttributeValues(a.cfg.memberOfAttribute), nil
}

// groupsFromSearch searches the group tree for entries naming the user.
func (a *Authenticator) groupsFromSearch(ctx context.Context, r *resolved, username string) ([]string, error) {
	seen := make(map[string]struct{}, 8)
	out := make([]string, 0, 8)

	frontier := []string{r.dn}

	depth := a.cfg.nestedGroupDepth
	if !a.cfg.nestedGroups || a.cfg.activeDirectoryChain {
		depth = 1
	}

	for level := 0; level < depth && len(frontier) > 0; level++ {
		var next []string

		for _, memberDN := range frontier {
			entries, err := a.searchGroups(ctx, r, memberDN, username)
			if err != nil {
				return nil, err
			}

			for _, entry := range entries {
				key := strings.ToLower(entry.DN)

				if _, dup := seen[key]; dup {
					continue
				}

				seen[key] = struct{}{}
				out = append(out, a.groupLabel(entry))
				next = append(next, entry.DN)
			}
		}

		frontier = next
	}

	return out, nil
}

func (a *Authenticator) searchGroups(ctx context.Context, r *resolved, memberDN, username string) ([]*ldap.Entry, error) {
	filter := a.cfg.groupFilter.expandFilter(map[string]string{
		placeholderUserDN:   memberDN,
		placeholderUsername: username,
		placeholderBaseDN:   a.cfg.groupBaseDN,
	})

	request := ldap.NewSearchRequest(
		a.cfg.groupBaseDN,
		a.cfg.groupScope,
		a.cfg.userDerefAliases,
		0,
		a.searchTimeLimit(),
		false,
		filter,
		[]string{a.cfg.groupNameAttribute},
		nil,
	)

	var entries []*ldap.Entry

	_, err := a.onConn(ctx, r, func(conn Conn) (*ldap.Entry, error) {
		result, serr := a.search(conn, request)
		if serr != nil {
			return nil, serr
		}

		entries = result.Entries

		return nil, nil
	})
	if err != nil {
		return nil, &AuthError{
			Op:         "group search",
			Username:   a.cfg.safeUsername(username),
			ResultCode: resultCode(err),
			Err:        err,
		}
	}

	return entries, nil
}

// namesFor turns group DNs into whatever Principal.Groups should hold.
func (a *Authenticator) namesFor(r *resolved, dns []string) ([]string, error) {
	out := make([]string, 0, len(dns))

	for _, dn := range dns {
		if a.cfg.groupsAsDN {
			out = append(out, dn)

			continue
		}

		if name, ok := r.groupNames[strings.ToLower(dn)]; ok {
			out = append(out, name)

			continue
		}

		out = append(out, rdnValue(dn, a.cfg.groupNameAttribute))
	}

	return out, nil
}

// groupLabel is the label for a group entry: its DN, or the configured
// name attribute, falling back to the DN's first RDN when the directory
// did not return the attribute.
func (a *Authenticator) groupLabel(entry *ldap.Entry) string {
	if a.cfg.groupsAsDN {
		return entry.DN
	}

	if name := entry.GetAttributeValue(a.cfg.groupNameAttribute); name != "" {
		return name
	}

	return rdnValue(entry.DN, a.cfg.groupNameAttribute)
}

// rememberGroupName notes a DN-to-name mapping seen during a nested walk,
// so that the memberOf path can report the real attribute value rather than
// a parsed RDN for the groups it happened to read.
//
// The memo lives on the request, not on the authenticator. A process-wide
// map of every group DN ever seen would be a cache nobody asked for, with
// no bound and no invalidation.
func (r *resolved) rememberGroupName(attribute string, entry *ldap.Entry) {
	name := entry.GetAttributeValue(attribute)
	if name == "" || entry.DN == "" {
		return
	}

	if r.groupNames == nil {
		r.groupNames = make(map[string]string, 8)
	}

	r.groupNames[strings.ToLower(entry.DN)] = name
}

// rdnValue extracts a name from a DN without a round trip.
//
// Under GroupsFromMemberOf all the directory gives us is a list of DNs,
// and asking it for each group's name would undo the one advantage that
// source has. The first RDN of a group DN is its naming attribute, and for
// every directory that maintains memberOf that attribute is the one
// configured as the group name — so parsing it is right in the case that
// matters and honest about the case that does not: when the RDN turns out
// to be some other attribute, the whole DN is returned rather than a value
// that looks like a name and is not.
func rdnValue(dn, wantType string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return dn
	}

	first := parsed.RDNs[0].Attributes[0]

	if !strings.EqualFold(first.Type, wantType) {
		return dn
	}

	return first.Value
}

// onConn runs fn on the best connection available: the service-account
// pool when there is one, and otherwise the user's own connection.
//
// The fallback is what lets a direct-bind deployment resolve groups with
// no privileged account at all. It has a real consequence, and it is the
// one worth knowing: the group search then runs with the user's own read
// permissions, so a directory that hides the group tree from ordinary
// users returns an empty group list rather than an error.
func (a *Authenticator) onConn(ctx context.Context, r *resolved, fn func(Conn) (*ldap.Entry, error)) (*ldap.Entry, error) {
	if a.pool != nil {
		return a.withPooledConn(ctx, fn)
	}

	if r.conn == nil {
		return nil, ErrClosed
	}

	return fn(r.conn)
}
