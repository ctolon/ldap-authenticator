# Security

Each invariant here has a test named after what it protects. This document
is the reasoning behind them.

## The empty password

RFC 4511, section 4.2: a simple bind carrying a zero-length password is an
*unauthenticated* bind request. A conforming server answers it with
success. So a directory that rejects the wrong password will accept no
password at all, and an authenticator that passes the empty string through
reports every existing DN as authenticated.

This is not hypothetical. It is the single most common way to build an
authentication bypass on top of LDAP, and it happens because the code that
does it looks correct:

```go
// Wrong, and it looks fine.
if err := conn.Bind(dn, password); err != nil {
    return ErrUnauthorized
}
return nil
```

This package refuses an empty password in `checkCredentials`, before a
connection is opened. go-ldap refuses to send one too, and has since v3.4 —
two guards against the one mistake that turns an authenticator into a door
is the right number.

The in-memory directory in `ldaptest` models the server's behaviour
faithfully, accepting the empty-password bind, so that the test asserting
this package never sends one is asserting something rather than agreeing
with a fake.

## Filter injection

A search filter is a grammar, and a username spliced into it raw is an
injection:

```
filter:   (uid=%s)
username: *)(uid=*
result:   (uid=*)(uid=*)
```

That matches every entry in the subtree. Under search-then-bind, the
package then binds as whichever entry came back — which, on most
directories, is whichever one the index happened to return first.

The fix is `ldap.EscapeFilter`, and it is what this package uses:

```go
// The practice, written out. This is correct.
safe := ldap.EscapeFilter(rawUsername)
filter := fmt.Sprintf("(&(objectClass=person)(uid=%s))", safe)
```

What this package does is the same thing with the `Sprintf` replaced by a
template that is parsed once, at startup:

```go
ldapauth.WithUserSearch("ou=people,dc=corp,dc=example",
    "(&(objectClass=person)(uid={{username}}))")
```

The escaping is not the difference — it is `ldap.EscapeFilter` underneath
either way. Three other things are:

**There is no unescaped path.** A `Sprintf` is correct on the line where
somebody remembered the `EscapeFilter`, and the next person writing the
next filter has to remember it again. Here the only way to get a value into
a filter is through the template, and the template escapes.

**Each placeholder is escaped for its own grammar.** A filter value and a
DN component need different escaping, and using one where the other belongs
is a bug that looks correct. Escaping a username as a filter value leaves
its commas alone — which is right for a filter and useless for a DN, where
a comma adds a component and moves the entry into another subtree.
[`examples/escaping`](../examples/escaping) prints both, side by side, and
the DN case is the one that surprises people.

**A DN in a filter is escaped like anything else.** It is tempting to
exempt `{{user_dn}}` and `{{base_dn}}` on the grounds that a DN is
structure rather than a value, and that escaping would corrupt its commas.
Both halves of that are wrong, and this package shipped the mistake right
up to the release candidate for v1.0.

`ldap.EscapeFilter` escapes `(`, `)`, `*`, `\`, NUL, and bytes above 0x7f.
Commas, equals signs and spaces pass through untouched, so an escaped DN
still compares equal to the entry it names. What does *not* pass through is
an asterisk — and under a direct bind, `{{user_dn}}` is built from the
username:

```
username:  x*
bind DN:   uid=x*,ou=people,dc=corp,dc=example      (valid; RFC 4514 does not escape *)
filter:    (member=uid=x*,ou=people,dc=corp,dc=example)
```

That is not a membership test any more. It is a prefix match, and it hands
the caller every group containing anybody whose DN starts `uid=x`. A failed
login is an inconvenience; this was an authorisation bypass, and it was
reachable by anybody who could influence their own account name.

Every placeholder in a filter is now escaped for RFC 4515, with no
exceptions. `TestAUsernameCannotWidenAGroupFilter` is the regression test,
`TestAnEscapedDNStillMatchesItsEntry` is the one that keeps the fix from
being "escape everything and break DN matching", and
`FuzzGroupFilterStaysOneTerm` asserts the property over arbitrary input.

`FuzzEscapeFilterValue` asserts the property directly: whatever the input,
the output contains no unescaped filter structure. `FuzzUserSearchFilterStaysOneTerm`
asserts it end to end, through the whole package: whatever the username,
the filter that reaches the directory still has the one term the template
described and no wildcard it did not contain.

## DN injection

A distinguished name is also a grammar, with a different escape set:

```
template: uid=%s,ou=people,dc=corp,dc=example
username: admin,ou=admins
result:   uid=admin,ou=admins,ou=people,dc=corp,dc=example
```

The username has added a component and moved the entry into another
subtree. RFC 4514 escaping turns the comma into `\,`, and the whole thing
becomes one RDN value again.

`FuzzEscapeDNValue` asserts the property the way it matters: it builds the
DN, parses it back with go-ldap's own parser, and requires that the result
has exactly the number of components the template had.

## Account enumeration

`Authenticate` returns `ErrInvalidCredentials` for a wrong password and for
a user that does not exist. The two are indistinguishable to the caller on
purpose. A caller who could tell them apart would be an oracle for anybody
who can reach them, and the flattening would have to be re-implemented, and
occasionally forgotten, in every application built on this package.

Timing is the other half of that oracle, and it cannot be closed the same
way: a search that matches nothing returns sooner than a search that
matches and then binds. `httpauth.WithMinimumDuration` pads every answer to
a floor, which moves the difference below the noise of the network in front
of it. It is not a constant-time guarantee, and nothing built on a
directory round trip can be.

## Identity leaking through a pooled connection

The pool holds connections bound as the service account. A user's bind
happens on a connection of its own, closed afterwards.

Rebinding a pooled connection as the user is an easy optimisation to reach
for and an authorisation bypass to live with: the connection carries that
user's identity into whichever request takes it next, and the searches that
request makes run with their permissions. `TestUserBindNeverSharesTheServiceConnection`
is the regression test.

## Retrying a rejected credential

Directories with a lockout policy count failed binds. A library that
retried them would turn one typo into three strikes and lock the account
out, and the operator would see an account lockout storm with no
explanation.

`retriable` returns false for `ErrInvalidCredentials` and for every other
answer the directory actually gave. It returns true for failures that say
nothing about the answer: a broken connection, a busy server, a server
going down.

## Plaintext

A simple bind sends the password as a length-prefixed string with no
encoding at all. Anyone on the path reads it.

`New` refuses a plaintext `ldap://` URL unless StartTLS is configured or
`WithInsecureNoTLS` is passed. The option is named the way it is so that
the refusal cannot be silenced without leaving evidence in the source, and
so that a reviewer grepping for `Insecure` finds it.

`ldapi://` is exempt: a unix domain socket never leaves the host, and its
access control is the filesystem's.

## What is logged, and what is not

The package logs stages, outcomes, counts, and errors. It logs the
username, or `[redacted]` under `WithUsernameRedaction`.

It never logs a password, a service-account password, or an attribute
value. There is no logging helper in the package that takes a password,
which is the cheapest way to guarantee none is written.

## What is cached, and what is not

The cache key is `HMAC-SHA256(secret, username || 0x00 || password)`, where
the secret is 32 bytes from the system CSPRNG, generated when the
authenticator is built and never written down. The value is the outcome. A
memory dump yields no password and nothing a password can be recovered
from, and two runs of the same program produce unrelated keys for the same
credentials.

The key is derived before the `Cache` is reached, so an implementation —
including one that stores things in Redis, on another machine, for other
replicas to read — never sees a credential.

`WithCacheSecret` replaces the generated secret with one you supply, which
is how several replicas agree on keys. It is a real secret: anybody holding
it can test a guessed credential against the cache offline, without
touching the directory and without the directory noticing. Keep it where
you keep the service account password, and understand that a cache shared
between two services makes one service's authentication decisions into the
other's.

What caching costs is freshness: for the length of the TTL, a disabled
account, a changed password, or a revoked group membership still works.
`MaxCacheTTL` caps that at five minutes and there is no option to raise it.
`InvalidateUser` drops an account's entries early, for when you have just
changed somebody's password and would rather not wait.

Failures that are not about the credential — the directory was down, the
context expired — are never cached. Caching those would serve the outage
back to the caller for the length of the TTL.

## Coalescing

With caching on, identical logins arriving at the same time are collapsed
into one round trip, and the waiters are handed a clone of the result.

The thing to be satisfied about is that this shares nothing between
different credentials. The key is the same HMAC the cache uses, over the
username and the password, so two callers who collapse into one are two
callers who presented exactly the same credential — and the answer for one
is by definition the answer for the other. A caller who presents a
different password gets a different key and a round trip of their own.

## Input hygiene

A username is rejected before any network call if it is empty, longer than
`WithUsernameMaxLength`, not valid UTF-8, or contains a control character.
A NUL in a username is trying to truncate a string somewhere downstream; a
newline is trying to forge a second line in a log. Neither is a username.

A password longer than `WithPasswordMaxLength` is rejected the same way.
That is not about password strength; it is about not carrying a megabyte
from a request body to a directory, once per request, for as long as
somebody cares to send one.

## What is proved, and how

Every invariant above has a test named after what it protects. Three of
them are also fuzzed as end-to-end properties rather than as unit
behaviour, which is a stronger statement than a table of known-bad inputs:

- `FuzzSearchThenBindAdmitsOnlyTheRealUser` — for any username and any
  password, either the authentication fails with a documented error, or it
  succeeds and the credential really was the right one.
- `FuzzDirectBindStaysInsideItsSubtree` — for any username, every DN the
  package binds as has exactly the components the template had and sits
  under the configured subtree.
- `FuzzUserSearchFilterStaysOneTerm` — for any username, the filter that
  reaches the directory still has one term and no wildcard the template did
  not contain.

The in-memory directory those run against parses filters and DNs for real,
so a passing run means the property held against a parser rather than
against a string comparison. It has its own tests for the same reason: a
fake that unescaped too eagerly would report every attack as harmless.

## What this library cannot do for you

It cannot tell you whether your service account has more access than it
needs, whether your TLS certificate is verified by anything, or whether the
group whose name you put in an authorisation rule is the group you meant.
Group *names* are not unique — two subtrees can each hold a group called
`admins` — which is why `WithGroupDNs` exists and why an authorisation rule
that matters should probably use it.
