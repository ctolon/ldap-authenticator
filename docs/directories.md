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

## Referrals, and multi-domain forests

A referral is the directory saying "not in this partition, try over there".
On a single-domain deployment you will never see one. On a forest they are
routine, and they are the failure mode most likely to waste a day.

**Referrals alongside entries are normal.** A search that crosses a
partition boundary comes back with continuation references for the parts it
did not cover. The entries it did return are still the answer, and this
package treats them that way.

**Referrals instead of entries mean the base DN names the wrong
partition.** The user exists; they are just not under the base you searched.
Without help, that arrives as "no such user" and sends somebody hunting
through the directory for an account sitting exactly where it should be.

```go
ldapauth.WithReferralPolicy(ldapauth.ReferralFail)
```

turns that into `ErrReferral`, with the URLs on the `AuthError`:

```go
var authErr *ldapauth.AuthError
if errors.As(err, &authErr) && errors.Is(err, ldapauth.ErrReferral) {
    log.Printf("base DN is in the wrong partition; the directory suggests %v", authErr.Referrals)
}
```

The default is to ignore them and log a warning, because that is what every
version of this package has done and changing it would break deployments
that upgrade. Turn it on once you are confident your base DNs are right, so
that the day they stop being right you are told.

**This package does not follow referrals, and will not.** Following one
means opening a connection to a host the directory named and presenting the
service account's password to it. A directory that can be persuaded to
return a referral is then a directory that can be persuaded to collect
credentials, and "the directory told us to" is not a trust boundary. The
supported answers are:

- **Point the base DN at the right partition.** Usually the fix.
- **Use the Global Catalog** for a forest-wide search: port 3268, or 3269
  for `ldaps://`. One search covers every domain. The catch is that the GC
  holds a *partial* attribute set — check that the attributes you read are
  replicated to it, because `memberOf` is and plenty of custom attributes
  are not.
- **Configure one authenticator per domain** and try them in turn, if the
  user population is genuinely split and you need full attributes. That is
  a decorator over `ldapauth.Authenticator`; see
  [extending.md](extending.md).

A note on the Global Catalog and groups: a GC search sees group membership
across the forest, which is the whole reason to use it, but universal
groups only. Domain-local groups are not in the GC, so an authorisation
rule written against one will silently never match.

## Why Active Directory refused

AD answers every refused bind with `invalid credentials`, and puts the real
reason in the error text as a hexadecimal code. This package reads it, and
puts it on the error as a [`RejectionReason`](configuration.md):

```go
identity, err := auth.Authenticate(ctx, username, password)
if err != nil {
    audit.Record(username, ldapauth.ReasonFor(err))   // password-expired, account-disabled, ...
    return unauthorized()                             // the same answer, whatever the reason
}
```

| AD code | reason | actionable |
|---|---|---|
| `525` | `ReasonNoSuchUser` | yes |
| `52e` | `ReasonBadPassword` | yes |
| `530` | `ReasonTimeRestricted` | no |
| `531` | `ReasonWorkstationRestricted` | no |
| `532` | `ReasonPasswordExpired` | no |
| `533` | `ReasonAccountDisabled` | no |
| `701` | `ReasonAccountExpired` | no |
| `773` | `ReasonPasswordMustChange` | no |
| `775` | `ReasonAccountLocked` | no |

"Actionable" means trying again with different credentials might work. It
is the distinction a help desk cares about, and a rise in unactionable
refusals is an operational event rather than an attack.

**Send the user the same response regardless.** `Authenticate` returns
`ErrInvalidCredentials` for every one of these on purpose: a login form
that could tell "password expired" from "wrong password" is a slower
account enumeration oracle, but it is still one. The reason is for your
log, your audit trail, and your metric label.

For OpenLDAP and 389 Directory Server the same information arrives through
the password policy control, with `WithPasswordPolicyControl()`. AD needs
nothing extra.

**Account lockout.** AD counts failed binds and locks accounts, which means
anybody who knows a username can lock it out. This package never retries a
rejected credential for exactly that reason, and
`WithLockoutProtection` stops the attempts reaching the directory at all —
see [security.md](security.md).

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
