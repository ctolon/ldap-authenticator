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

Every value this package interpolates into a filter goes through RFC 4515
escaping, which turns `(`, `)`, `*`, `\`, and everything outside 7-bit
ASCII into `\xx` pairs. There is no exported function that interpolates
without escaping. `FuzzEscapeFilterValue` asserts the property directly:
whatever the input, the output contains no unescaped filter structure.

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

What caching costs is freshness: for the length of the TTL, a disabled
account, a changed password, or a revoked group membership still works.
`MaxCacheTTL` caps that at five minutes and there is no option to raise it.
`InvalidateUser` drops an account's entries early, for when you have just
changed somebody's password and would rather not wait.

Failures that are not about the credential — the directory was down, the
context expired — are never cached. Caching those would serve the outage
back to the caller for the length of the TTL.

## Input hygiene

A username is rejected before any network call if it is empty, longer than
`WithUsernameMaxLength`, not valid UTF-8, or contains a control character.
A NUL in a username is trying to truncate a string somewhere downstream; a
newline is trying to forge a second line in a log. Neither is a username.

## What this library cannot do for you

It cannot tell you whether your service account has more access than it
needs, whether your TLS certificate is verified by anything, or whether the
group whose name you put in an authorisation rule is the group you meant.
Group *names* are not unique — two subtrees can each hold a group called
`admins` — which is why `WithGroupDNs` exists and why an authorisation rule
that matters should probably use it.
