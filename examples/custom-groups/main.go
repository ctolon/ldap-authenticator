// Command custom-groups resolves group membership from somewhere the
// directory is not, and shows how to combine that with what the directory
// does know.
//
//	go run ./examples/custom-groups
//
// WithGroupResolver replaces the built-in resolution rather than adding to
// it, so a resolver that wants both has to ask the directory itself. That
// is what the Searcher in the request is for: it runs on the
// authenticator's connection, with the authenticator's identity, and it
// cannot bind, write, or be retained past the call.
package main

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/go-ldap/ldap/v3"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const (
	peopleDN = "ou=people,dc=example,dc=com"
	groupsDN = "ou=groups,dc=example,dc=com"
)

// entitlements stands in for the service that actually knows what people
// are allowed to do — a table, an internal API, a feature-flag system.
var entitlements = map[string][]string{
	"uid=alice,ou=people,dc=example,dc=com": {"billing:read", "billing:write"},
	"uid=bob,ou=people,dc=example,dc=com":   {"billing:read"},
}

func main() {
	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://in-memory"),
		ldapauth.WithDialer(directory().Dialer()),
		ldapauth.WithServiceAccount("cn=svc,dc=example,dc=com", "svc-password"),
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),

		ldapauth.WithGroupResolver(ldapauth.GroupResolverFunc(resolve)),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}

	defer func() { _ = auth.Close() }()

	for _, username := range []string{"alice", "bob"} {
		identity, err := auth.Authenticate(context.Background(), username, username+"-password")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", username, err)

			continue
		}

		fmt.Printf("%-6s %v\n", username, identity.GetGroups())
	}
}

// resolve combines the directory's groups with the entitlement service's,
// and prefixes each so that an authorisation rule can tell them apart.
//
// It runs inside the caller's context and inside the retry loop, so it has
// to be quick and it has to be safe to run twice.
func resolve(ctx context.Context, request ldapauth.GroupRequest) ([]string, error) {
	fromDirectory, err := directoryGroups(ctx, request)
	if err != nil {
		return nil, err
	}

	groups := make([]string, 0, len(fromDirectory)+4)

	for _, group := range fromDirectory {
		groups = append(groups, "ldap:"+group)
	}

	// A failure here would fail the authentication, which is a policy
	// decision worth making on purpose. Failing open — logging and
	// carrying on with the directory's groups alone — is the other
	// reasonable answer, and it is the one to pick when the entitlement
	// service is less available than the directory.
	for _, entitlement := range entitlements[request.DN] {
		groups = append(groups, "entitlement:"+entitlement)
	}

	slices.Sort(groups)

	return groups, nil
}

// directoryGroups asks the directory the question the built-in resolver
// would have asked, over the connection it would have used.
func directoryGroups(ctx context.Context, request ldapauth.GroupRequest) ([]string, error) {
	// The DN goes into the filter unescaped, which is correct here and
	// worth being explicit about: request.DN is a distinguished name the
	// directory itself returned, not caller input, and escaping it as a
	// filter value would turn its commas into literal characters so that
	// it matched nothing. A *username* in this position would need
	// ldap.EscapeFilter — see examples/escaping.
	result, err := request.Search.Search(ctx, ldap.NewSearchRequest(
		groupsDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectClass=groupOfNames)(member="+request.DN+"))",
		[]string{"cn"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("searching groups for %s: %w", request.Username, err)
	}

	groups := make([]string, 0, len(result.Entries))

	for _, entry := range result.Entries {
		if name := entry.GetAttributeValue("cn"); name != "" {
			groups = append(groups, name)
		}
	}

	return groups, nil
}

func directory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User("uid=alice,"+peopleDN, "alice-password").
			With("uid", "alice").With("objectClass", "inetOrgPerson"),
		ldaptest.User("uid=bob,"+peopleDN, "bob-password").
			With("uid", "bob").With("objectClass", "inetOrgPerson"),
		ldaptest.User("cn=svc,dc=example,dc=com", "svc-password").
			With("objectClass", "person"),

		ldaptest.Group("cn=developers,"+groupsDN).
			With("cn", "developers").
			With("objectClass", "groupOfNames").
			With("member", "uid=alice,"+peopleDN),

		ldaptest.Group("cn=support,"+groupsDN).
			With("cn", "support").
			With("objectClass", "groupOfNames").
			With("member", "uid=bob,"+peopleDN),
	)
}
