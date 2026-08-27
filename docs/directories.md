# Directories

What to configure for the directory you actually have. Everything here is
about the directory's conventions rather than about this package; the
package's own options are in [configuration.md](configuration.md).

## Active Directory

```go
ldapauth.New(
    ldapauth.WithURLs(
        "ldaps://dc1.corp.example:636",
        "ldaps://dc2.corp.example:636",
    ),
    ldapauth.WithServiceAccount("CN=svc-ldap,OU=Service,DC=corp,DC=example", password),
    ldapauth.WithUserSearch("DC=corp,DC=example",
        "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={{username}})(userPrincipalName={{username}})))"),
    ldapauth.WithActiveDirectoryGroups("DC=corp,DC=example"),
    ldapauth.WithDisplayNameAttribute("displayName"),
    ldapauth.WithEmailAttribute("mail"),
    ldapauth.WithPagingSize(1000),
)
```

**Logging in.** Users type one of three things, and which one is a
decision your organisation already made:

| | example | attribute |
|---|---|---|
| Down-level name | `alice` | `sAMAccountName` |
| User principal name | `alice@corp.example` | `userPrincipalName` |
| Down-level with domain | `CORP\alice` | — |

The filter above accepts the first two. For a direct bind, AD is unusual in
accepting the UPN or the down-level name in place of a DN:

```go
ldapauth.WithDirectBind("{{username}}@corp.example")
ldapauth.WithDirectBind(`CORP\{{username}}`)
```

That is the cheapest configuration there is — one round trip, no service
account — and it works whenever everybody's UPN suffix is the same.

**`objectCategory` before `objectClass`.** `objectCategory=person` is
indexed and single-valued; `objectClass=user` is neither. Putting the
indexed term first is the difference between a search and a scan on a large
directory.

**Paging is not optional.** AD caps a search at 1000 entries by default and
truncates silently past it. A group search on a large directory without
`WithPagingSize` returns a group list that is quietly incomplete.

**Groups.** `WithActiveDirectoryGroups` uses the
`LDAP_MATCHING_RULE_IN_CHAIN` matching rule, OID
`1.2.840.113556.1.4.1941`, which has the server compute transitive
membership itself. One search, complete answer, no walking. It is an AD
extension: against anything else it returns no entries rather than an
error, which looks exactly like a user in no groups.

`memberOf` also works and costs nothing, but AD does not put a user's
*primary* group in it — usually `Domain Users`. If that matters, the
matching rule does include it.

**Referrals.** AD returns referrals for objects in other domains, and
go-ldap does not chase them. Point the base DN at the domain you mean, or
use the Global Catalog on port 3268 (`ldaps://` 3269) for a forest-wide
read — but note that the Global Catalog holds a partial attribute set, so
check that what you are reading is in it.

**Account lockout.** AD counts failed binds and locks accounts. This
package never retries a rejected credential for exactly that reason, and
`WithNegativeCache` blunts a client looping on a stale password. What it
cannot help with is a *disabled* account: AD answers a bind for one with
`invalid credentials` and a `data 533` sub-code, which this package
reports as `ErrInvalidCredentials` like any other rejection. Read
`AuthError` if you need the distinction:

```go
var authErr *ldapauth.AuthError
if errors.As(err, &authErr) {
    log.Println(authErr.ResultCode, authErr.Err)   // the sub-code is in the wrapped text
}
```

## OpenLDAP

```go
ldapauth.New(
    ldapauth.WithURL("ldaps://ldap.corp.example:636"),
    ldapauth.WithServiceAccount("cn=readonly,dc=corp,dc=example", password),
    ldapauth.WithUserSearch("ou=people,dc=corp,dc=example",
        "(&(objectClass=inetOrgPerson)(uid={{username}}))"),
    ldapauth.WithGroupSearch("ou=groups,dc=corp,dc=example",
        "(&(objectClass=groupOfNames)(member={{user_dn}}))"),
    ldapauth.WithNestedGroups(),
    ldapauth.WithEmailAttribute("mail"),
)
```

**Direct bind usually works.** OpenLDAP deployments tend to have everybody
under one subtree with `uid` as the naming attribute, which is exactly the
case direct bind is for:

```go
ldapauth.WithDirectBind("uid={{username}},ou=people,dc=corp,dc=example")
```

**`memberOf` is not there by default.** The `memberof` overlay has to be
configured, and until it is, `WithMemberOfGroups` returns nothing — which
looks exactly like a user in no groups. Check before assuming:

```sh
ldapsearch -x -H ldaps://ldap.corp.example -D "$SERVICE_DN" -W \
  -b "uid=alice,ou=people,dc=corp,dc=example" memberOf
```

If it comes back empty, use `WithGroupSearch`.

**posixGroup lists members by name, not by DN:**

```go
ldapauth.WithGroupSearch("ou=groups,dc=corp,dc=example",
    "(&(objectClass=posixGroup)(memberUid={{username}}))")
```

**ACLs are the usual answer.** OpenLDAP answers a search whose base the
bound identity may not see with `no such object` rather than
`insufficient access`. A service account without read access therefore
looks like a missing entry. See [troubleshooting.md](troubleshooting.md).

**A unix socket is the most secure transport there is**, and this package
treats it as such: `ldapi:///var/run/ldapi` needs no TLS opt-out, because a
socket never leaves the host and its access control is the filesystem's.

## 389 Directory Server, Red Hat DS, FreeIPA

Close enough to OpenLDAP to configure the same way, with three
differences:

- `memberOf` is maintained by default, so `WithMemberOfGroups` works.
- FreeIPA puts users under `cn=users,cn=accounts,$SUFFIX` and groups under
  `cn=groups,cn=accounts,$SUFFIX`.
- Nested groups are real and common, so `WithNestedGroups` is usually
  wanted.

```go
ldapauth.WithUserSearch("cn=users,cn=accounts,dc=corp,dc=example", "(uid={{username}})"),
ldapauth.WithMemberOfGroups(),
ldapauth.WithNestedGroups(),
```

## Directory-agnostic advice

**Prefer direct bind when you can.** One round trip, no privileged account
in your configuration, and nothing privileged to leak out of it.

**Give the service account read and nothing else.** It never needs to
write, and it never needs to read `userPassword` — this package verifies a
password by binding, never by reading or comparing one.

**Put the indexed term first in a filter,** and include an `objectClass`
term. A filter that matches two entries is `ErrAmbiguousUser`, and the
usual cause is a missing `objectClass`.

**Check what you configured with `ldapsearch` before blaming the library.**
Nine times in ten, a search that fails here fails there too, and the
message is more direct:

```sh
ldapsearch -x -H ldaps://dc1.corp.example:636 \
  -D 'cn=readonly,dc=corp,dc=example' -W \
  -b 'ou=people,dc=corp,dc=example' '(uid=alice)' dn memberOf
```
