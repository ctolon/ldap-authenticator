package ldapauth

import (
	"context"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// A Searcher runs a search against the directory on the authenticator's
// behalf.
//
// It is what a [GroupResolver] is handed instead of a connection: the
// authenticator decides which identity the search runs as — the pooled
// service account where there is one, the user's own connection otherwise
// — applies the configured paging, and keeps the connection's lifetime to
// itself. A resolver cannot bind, cannot write, and cannot hold the
// connection past the call it was given.
type Searcher interface {
	// Search runs one search and returns its result. The context bounds
	// the call, and the request must not be retained or mutated
	// afterwards.
	Search(ctx context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, error)
}

// SearcherFunc adapts a function to [Searcher].
type SearcherFunc func(ctx context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, error)

// Search calls f.
func (f SearcherFunc) Search(ctx context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return f(ctx, request)
}

// GroupRequest is what a [GroupResolver] is asked about.
type GroupRequest struct {
	// Username is the username as supplied to Authenticate.
	Username string

	// DN is the distinguished name that was authenticated.
	DN string

	// Entry is the user's directory entry, or nil when the configuration
	// read none. The resolver must not retain it.
	Entry *ldap.Entry

	// Search runs searches against the directory. It is valid only for the
	// duration of the call.
	Search Searcher
}

// A GroupResolver produces the groups an authenticated identity belongs
// to.
//
// The default resolves them from the directory, in whichever of the three
// ways the configuration asked for. Replace it when membership lives
// somewhere the directory is not — an entitlements service, a mapping
// table, a static list for a break-glass account — or when your directory
// has a group scheme this package does not model.
//
// It runs inside the caller's context and inside the retry loop, so it
// should be quick and it must not have side effects that would be wrong to
// repeat. An error it returns fails the authentication.
type GroupResolver interface {
	// ResolveGroups returns the groups the request's identity belongs to,
	// as names or as DNs — whichever the rest of the application expects.
	// Returning an empty slice and a nil error means "no groups", which
	// is a legitimate answer; returning an error fails the
	// authentication.
	ResolveGroups(ctx context.Context, request GroupRequest) ([]string, error)
}

// GroupResolverFunc adapts a function to [GroupResolver].
type GroupResolverFunc func(ctx context.Context, request GroupRequest) ([]string, error)

// ResolveGroups calls f.
func (f GroupResolverFunc) ResolveGroups(ctx context.Context, request GroupRequest) ([]string, error) {
	return f(ctx, request)
}

// NoGroups is a [GroupResolver] that resolves nothing. It is what the
// package uses when group resolution is disabled, and it is a useful base
// for a resolver that only sometimes has an answer.
type NoGroups struct{}

// ResolveGroups returns no groups and no error.
func (NoGroups) ResolveGroups(context.Context, GroupRequest) ([]string, error) { return nil, nil }

// directoryGroups is the [GroupResolver] this package implements.
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
type directoryGroups struct {
	cfg *config

	// names memoises group DN to group name for the duration of one
	// request, and is allocated on first use — only a nested memberOf
	// walk ever reads a group's entry, and only that walk has anything to
	// remember. It belongs to the request rather than to the resolver: a
	// process-wide map of every group DN ever seen would be a cache
	// nobody asked for, with no bound and no invalidation.
	names map[string]string
}

func (g *directoryGroups) ResolveGroups(ctx context.Context, request GroupRequest) ([]string, error) {
	switch g.cfg.groupSource {
	case GroupsFromMemberOf:
		return g.perRequest().fromMemberOf(ctx, request)

	case GroupsFromSearch:
		return g.perRequest().fromSearch(ctx, request)

	default:
		return nil, nil
	}
}

// perRequest returns a copy to hold the request's own state.
//
// The resolver stored on the Client is shared by every goroutine, so
// nothing may be written to it. Group resolution is off by default, so
// this allocates nothing at all in the common case: the copy is made only
// once there is a group source to run.
func (g *directoryGroups) perRequest() *directoryGroups {
	return &directoryGroups{cfg: g.cfg}
}

// fromMemberOf reads the memberships off the user's own entry.
func (g *directoryGroups) fromMemberOf(ctx context.Context, request GroupRequest) ([]string, error) {
	if request.Entry == nil {
		return nil, nil
	}

	dns := request.Entry.GetAttributeValues(g.cfg.memberOfAttribute)

	if !g.cfg.nestedGroups || g.cfg.activeDirectoryChain {
		return g.labelsFor(dns), nil
	}

	// Walk upwards: each group is itself an entry that may carry its own
	// memberOf. One lookup per group per level, which is why the Active
	// Directory matching rule is worth using where it is available.
	seen := make(map[string]struct{}, len(dns)*2)
	ordered := make([]string, 0, len(dns)*2)

	frontier := dns

	for depth := 0; depth < g.cfg.nestedGroupDepth && len(frontier) > 0; depth++ {
		var next []string

		for _, dn := range frontier {
			key := strings.ToLower(dn)

			if _, dup := seen[key]; dup {
				continue
			}

			seen[key] = struct{}{}
			ordered = append(ordered, dn)

			next = append(next, g.parentsOf(ctx, request, dn)...)
		}

		frontier = next
	}

	return g.labelsFor(ordered), nil
}

// parentsOf reads one group's own memberOf attribute.
func (g *directoryGroups) parentsOf(ctx context.Context, request GroupRequest, dn string) []string {
	result, err := request.Search.Search(ctx, ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		g.cfg.userDerefAliases,
		1,
		g.cfg.searchTimeLimit(),
		false,
		"(objectClass=*)",
		[]string{g.cfg.memberOfAttribute, g.cfg.groupNameAttribute},
		nil,
	))
	if err != nil {
		// A group that cannot be read is a hole in the answer, not a
		// failed login. Nested expansion is best-effort by nature: the
		// directory may simply not let this identity read the group tree,
		// and refusing the authentication over it would be a worse
		// outcome than reporting the memberships that could be read.
		//
		// Worth a warning rather than a debug line: the login succeeded
		// and the group list it carries is incomplete, which is exactly
		// the kind of failure that shows up later as a mysterious
		// authorisation denial.
		g.cfg.logger.Warn("nested group lookup failed; the group list may be incomplete",
			"group", dn, "error", err)

		return nil
	}

	if len(result.Entries) == 0 {
		return nil
	}

	entry := result.Entries[0]
	g.remember(entry)

	return entry.GetAttributeValues(g.cfg.memberOfAttribute)
}

// fromSearch searches the group tree for entries naming the user.
func (g *directoryGroups) fromSearch(ctx context.Context, request GroupRequest) ([]string, error) {
	seen := make(map[string]struct{}, 8)
	out := make([]string, 0, 8)

	frontier := []string{request.DN}

	depth := g.cfg.nestedGroupDepth
	if !g.cfg.nestedGroups || g.cfg.activeDirectoryChain {
		depth = 1
	}

	for level := 0; level < depth && len(frontier) > 0; level++ {
		var next []string

		for _, memberDN := range frontier {
			entries, err := g.searchGroups(ctx, request, memberDN)
			if err != nil {
				return nil, err
			}

			for _, entry := range entries {
				key := strings.ToLower(entry.DN)

				if _, dup := seen[key]; dup {
					continue
				}

				seen[key] = struct{}{}
				out = append(out, g.label(entry))
				next = append(next, entry.DN)
			}
		}

		frontier = next
	}

	return out, nil
}

func (g *directoryGroups) searchGroups(ctx context.Context, request GroupRequest, memberDN string) ([]*ldap.Entry, error) {
	filter := g.cfg.groupFilter.expandFilter(map[string]string{
		placeholderUserDN:   memberDN,
		placeholderUsername: request.Username,
		placeholderBaseDN:   g.cfg.groupBaseDN,
	})

	result, err := request.Search.Search(ctx, ldap.NewSearchRequest(
		g.cfg.groupBaseDN,
		g.cfg.groupScope,
		g.cfg.userDerefAliases,
		0,
		g.cfg.searchTimeLimit(),
		false,
		filter,
		[]string{g.cfg.groupNameAttribute},
		nil,
	))
	if err != nil {
		if inner, ok := asAuthError(err); ok {
			return nil, inner.enrich("group search", g.cfg.safeUsername(request.Username))
		}

		return nil, &AuthError{
			Op:         "group search",
			Username:   g.cfg.safeUsername(request.Username),
			ResultCode: resultCode(err),
			Err:        err,
		}
	}

	return result.Entries, nil
}

// labelsFor turns group DNs into whatever the group list should hold.
func (g *directoryGroups) labelsFor(dns []string) []string {
	out := make([]string, 0, len(dns))

	for _, dn := range dns {
		switch {
		case g.cfg.groupsAsDN:
			out = append(out, dn)

		default:
			if name, ok := g.names[strings.ToLower(dn)]; ok {
				out = append(out, name)

				continue
			}

			out = append(out, rdnValue(dn, g.cfg.groupNameAttribute))
		}
	}

	return out
}

// label is the label for a group entry: its DN, or the configured name
// attribute, falling back to the DN's first RDN when the directory did not
// return the attribute.
func (g *directoryGroups) label(entry *ldap.Entry) string {
	if g.cfg.groupsAsDN {
		return entry.DN
	}

	if name := entry.GetAttributeValue(g.cfg.groupNameAttribute); name != "" {
		return name
	}

	return rdnValue(entry.DN, g.cfg.groupNameAttribute)
}

// remember notes a DN-to-name mapping seen during a nested walk, so that
// the memberOf path can report the real attribute value rather than a
// parsed RDN for the groups it happened to read.
func (g *directoryGroups) remember(entry *ldap.Entry) {
	name := entry.GetAttributeValue(g.cfg.groupNameAttribute)
	if name == "" || entry.DN == "" {
		return
	}

	if g.names == nil {
		g.names = make(map[string]string, 8)
	}

	g.names[strings.ToLower(entry.DN)] = name
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

// searcherFor builds the [Searcher] a group resolver is handed.
//
// It uses the service-account pool when there is one, and otherwise the
// user's own connection. The fallback is what lets a direct-bind
// deployment resolve groups with no privileged account at all. It has a
// real consequence, and it is the one worth knowing: the group search then
// runs with the user's own read permissions, so a directory that hides the
// group tree from ordinary users returns an empty group list rather than
// an error.
func (a *Client) searcherFor(r *resolved) Searcher {
	return SearcherFunc(func(ctx context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if a.pool != nil {
			var result *ldap.SearchResult

			_, err := a.withPooledConn(ctx, func(conn Conn) (*ldap.Entry, error) {
				var serr error
				result, serr = a.search(ctx, conn, request)

				return nil, serr
			})

			return result, err
		}

		if r == nil || r.conn == nil {
			return nil, ErrClosed
		}

		return a.search(ctx, r.conn, request)
	})
}
