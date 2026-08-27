# Bind strategies

There are two, and which one you can use is a question about your
directory.

## Direct bind

Format the username into a DN template and bind as it.

```go
ldapauth.WithDirectBind("uid={{username}},ou=people,dc=corp,dc=example")
ldapauth.WithDirectBind("{{username}}@corp.example")          // AD user principal name
ldapauth.WithDirectBind("CORP\\{{username}}")                 // AD down-level name
```

One round trip. No service account. Nothing privileged anywhere in the
configuration, which means nothing privileged to leak out of it.

Use it when every user lives under one subtree and logs in with the
attribute that names their entry. That covers most OpenLDAP deployments
and, through the UPN form, a great many Active Directory ones.

### Reading attributes without a service account

If you ask for attributes or groups, they have to be read from somewhere.
By default they are read over the user's own freshly bound connection, so
a direct-bind deployment can run with no service account at all.

The consequence: those reads run with the user's own permissions. A
directory that hides the group tree from ordinary users will return an
empty group list rather than an error. If that is your directory, configure
`WithServiceAccount` as well — the pool then exists, and the reads go
through it.

### What it cannot do

If the DN cannot be derived from the username, direct bind is not
available. That is the case when users are spread across subtrees, when
they log in with an email address that is not part of their DN, or when the
naming attribute is an opaque employee number that nobody types.

## Search then bind

A service account searches for the entry, and the password is verified by
binding as the DN the search returned.

```go
ldapauth.WithServiceAccount("cn=readonly,dc=corp,dc=example", os.Getenv("LDAP_SERVICE_PASSWORD")),
ldapauth.WithUserSearch(
    "ou=people,dc=corp,dc=example",
    "(&(objectClass=inetOrgPerson)(uid={{username}}))",
),
```

Three round trips: the service bind (usually amortised by the pool), the
search, and the user bind. In exchange, the username can be anything the
filter can match.

Let people log in with either a username or an email address:

```go
"(&(objectClass=inetOrgPerson)(|(uid={{username}})(mail={{username}})))"
```

### The service account

It needs read access to the user subtree, and to the group subtree if you
resolve groups. It never needs to write, and it never needs to read
`userPassword` — this package verifies a password by binding, never by
reading or comparing one. Grant it accordingly.

`WithAnonymousServiceBind` exists for the rare directory that answers
anonymous searches. It has to be asked for explicitly, because a directory
that permits anonymous search and a deployment that forgot its credentials
look identical from inside this package.

### Exactly one match, or nothing

A search that matches more than one entry is `ErrAmbiguousUser`, not a race
to pick the first. Binding as whichever entry came back first would make
the authenticated identity depend on server-side ordering.

If you are seeing it, the filter is too loose — usually a missing
`objectClass` term, or a base DN that spans two subtrees that both hold a
`uid=alice`.

A search that matches nothing is `ErrInvalidCredentials`, the same error a
wrong password produces. See [security.md](security.md).

## Templates

Both strategies take a template with `{{name}}` placeholders. The
placeholders available depend on where the template is used:

| | `{{username}}` | `{{base_dn}}` | `{{user_dn}}` |
|---|---|---|---|
| `WithDirectBind` | yes | — | — |
| `WithUserSearch` | yes | yes | — |
| `WithGroupSearch` | yes | yes | yes |

`{{username}}` is escaped for the grammar it lands in. `{{base_dn}}` and
`{{user_dn}}` are spliced verbatim, because they are DNs rather than values
— escaping them would turn their commas into literal characters — and
neither is ever derived from user input.

A single `%s` with no `{{...}}` anywhere is accepted as shorthand for
`{{username}}`, so existing configuration can be pasted in unchanged.

A template with an unknown placeholder, or with no placeholder at all, is a
`New` failure. The second case matters: a direct-bind template with no
`{{username}}` would bind as the same DN for every login, and the first
correct password anybody typed would authenticate everybody.

## Lookup, for when authentication happened elsewhere

```go
principal, err := auth.Lookup(ctx, username)
```

Reads the entry and resolves groups, with no password and no user bind. For
the case where a SAML assertion, a signed token, or an upstream proxy has
already established who somebody is, and the directory is still where their
attributes and groups live.

It needs a service account, since there is no user bind to borrow a
connection from. Unlike `Authenticate`, it returns `ErrUserNotFound` for a
missing user: the caller already knows who they are asking about, so there
is no oracle to protect.
