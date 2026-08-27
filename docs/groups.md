# Groups

Group resolution is off by default. It costs a round trip, and plenty of
applications only need to know that the password was right.

## The three sources

| | round trips | needs | nesting |
|---|---|---|---|
| `WithMemberOfGroups` | none | the `memberOf` attribute | walked client-side |
| `WithGroupSearch` | one per level | nothing | walked client-side |
| `WithActiveDirectoryGroups` | one, total | Active Directory | done by the server |

### memberOf

```go
ldapauth.WithMemberOfGroups()
```

The memberships arrive with the user's attributes, so they cost nothing
extra. Active Directory always maintains `memberOf`; OpenLDAP does when the
`memberof` overlay is configured, and does not otherwise — which looks
exactly like a user in no groups, so check before assuming.

Group *names* under this source are derived from the first RDN of each
group DN rather than by reading the group's entry, because reading them
would undo the one advantage the source has. For `cn=devs,ou=groups,...`
with the default `cn` name attribute, that gives `devs`. When the first RDN
is some other attribute, the whole DN is reported rather than a value that
looks like a name and is not.

### Group search

```go
ldapauth.WithGroupSearch("ou=groups,dc=corp,dc=example",
    "(&(objectClass=groupOfNames)(member={{user_dn}}))")
```

Searches the group tree for entries that name the user. Works on any
directory, including the ones where membership lives only on the group —
`posixGroup`, and `groupOfNames` without the overlay.

For `posixGroup`, membership is by name rather than DN:

```go
"(&(objectClass=posixGroup)(memberUid={{username}}))"
```

### The Active Directory matching rule

```go
ldapauth.WithActiveDirectoryGroups("OU=Groups,DC=corp,DC=example")
```

Uses `LDAP_MATCHING_RULE_IN_CHAIN`, OID `1.2.840.113556.1.4.1941`, which
has the server compute transitive membership itself. One search returns
every group the user is in, directly or through nesting — faster and more
complete than walking from the client.

The rule is an Active Directory extension. A directory that does not
implement it answers with no entries rather than with an error, which is
indistinguishable from a user in no groups. Do not enable it against
anything else.

## Nesting

```go
ldapauth.WithNestedGroups()
ldapauth.WithNestedGroupDepth(6)   // the default is 4
```

Under `memberOf`, one lookup per group per level. Under a group search, one
search per level. Both are bounded twice: by the configured depth, and by a
set of groups already visited.

Two bounds rather than one because a directory will happily let two groups
contain each other, and the visited set is what turns a cycle from an
infinite walk into a finite one — the depth cap is the backstop for the
case where the visited set is not enough, such as a very wide graph that
would otherwise take a long time to exhaust.

A group that cannot be read during a nested walk is logged at warning level
and left out of the result, rather than failing the login. The
authentication has already succeeded; refusing it because the group tree is
not readable would be a worse outcome than an incomplete group list. The
warning is there because an incomplete group list shows up later as a
mysterious authorisation denial.

## Names or DNs

```go
ldapauth.WithGroupDNs()
```

Group names are not unique. Two subtrees can each hold a `cn=admins`, and
an authorisation rule written against the name cannot tell them apart. DNs
can. If the group tree is large enough for that to be possible, use DNs.

Membership tests are case-insensitive either way, because directories match
names and DNs case-insensitively and a case-sensitive check here would be
one that passes in testing and fails against the directory that capitalises
differently.

## Requiring membership

In the application:

```go
if !identity.InAnyGroup("developers", "ops") {
    return errForbidden
}
```

Or in the middleware, where it becomes a 403 rather than a 401:

```go
httpauth.BasicAuth(auth,
    httpauth.RequireAnyGroup("developers", "ops"),
    httpauth.RequireAllGroups("employees"),
)
```

`InAnyGroup()` with no names is false and `InAllGroups()` with no names is
true. Both readings are the vacuous ones, and both are the safe ones: "in
any of nothing" should not admit anybody, and "no group is required" should
not reject anybody.

A group requirement with no group source configured rejects everybody,
because the principal arrives with no groups. That is a configuration
mistake worth watching for.

## When group resolution fails

The login fails with it, even though the password was already verified.
That is a choice, and the alternative is worse: returning the identity with
no groups hands the application a principal that looks like a real login by
somebody who belongs to nothing. Every `RequireAnyGroup` check reads that as
"not authorised" and every check that only asks whether somebody is logged
in reads it as "yes" — so a group server having a bad afternoon quietly
demotes everybody instead of locking them out, and a silent demotion is far
harder to notice than an outage.

Since a failure aborts the login, group resolution is on the critical path
in the way the directory is. If groups come from somewhere slower or less
reliable than the directory — an entitlements service, a database — that is
worth knowing before you point `WithGroupResolver` at it.

If your deployment would rather degrade than stop, say so in code by
wrapping the resolver:

```go
fallible := ldapauth.GroupResolverFunc(
    func(ctx context.Context, request ldapauth.GroupRequest) ([]string, error) {
        groups, err := inner.ResolveGroups(ctx, request)
        if err != nil {
            logger.Error("group resolution failed; logging in with none", "err", err)

            return nil, nil
        }

        return groups, nil
    },
)
```

Written out, the trade is visible in the code that made it. There is no
option for it, because an option would make it look like a tuning knob.

## When the directory is not where groups live

`WithGroupResolver` replaces all of the above with your own code, and hands
it a `Searcher` so it can still ask the directory when it wants to. See
[extending.md](extending.md).
