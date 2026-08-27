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
is how several replicas agree on keys.

### The shared cache secret is a credential

Anybody holding it can do this:

```text
candidate password  →  HMAC(secret, username ‖ 0 ‖ candidate)  →  look it up
```

A hit means the guess was right. No bind, no directory, no failed-login
counter, no log line — offline credential testing at whatever rate they can
read the cache. It is not as good as having the password hashes, because
they still need the cache and a username, but it is a great deal better
than nothing and it is silent.

What follows from that:

- **A different secret from the LDAP bind password.** They protect
  different things, and reusing one makes a compromise of either a
  compromise of both.
- **Thirty-two bytes.** That is what this package generates when you do not
  supply one. Sixteen is the hard floor for compatibility, and anything
  below thirty-two is logged as a warning at startup.
- **Rotate it on the same schedule as the bind password.** Rotation costs
  nothing but a cold cache: every key changes at once, so old entries
  become unreachable rather than wrong.
- **The store needs its own protections.** A Redis with no ACL and no TLS
  is a Redis where the cache is readable by whoever is on the network, and
  the secret only matters once somebody has the cache.

And the boundary: a cache shared between two services makes one service's
authentication decisions into the other's.

### The username in the store

The key hides the credential. The username travels beside it in the clear,
because `InvalidateUser` has to find an account's entries without knowing
the password — so a shared, remote, or backed-up store holds a list of who
has logged in recently, which is personal data this package put there.

```go
ldapauth.WithCacheUsernameHashing()
```

replaces it with a keyed hash under the same secret. Invalidation still
works, because it hashes the same way, and the store holds nothing anybody
can read. What it costs is the ability to look in the cache and see who is
in it, which is a real debugging affordance and the reason it is a choice.

What caching costs is freshness: for the length of the TTL, a disabled
account, a changed password, or a revoked group membership still works.
`MaxCacheTTL` caps that at five minutes and there is no option to raise it.
`InvalidateUser` drops an account's entries early, for when you have just
changed somebody's password and would rather not wait.

Failures that are not about the credential — the directory was down, the
context expired — are never cached. Caching those would serve the outage
back to the caller for the length of the TTL.

## Locking somebody out of their own account

A directory that locks an account after five failed binds is a directory
where anybody who knows a username can lock that account out. No access is
needed, no guessing, and nothing about it looks like an attack from the
directory's side — five wrong passwords is five wrong passwords. The victim
is the one who calls the help desk.

This package refuses to make it worse: a rejected credential is never
retried, so one attempt from a caller is one attempt at the directory.

`WithLockoutProtection` goes further and stops the attempts arriving:

```go
ldapauth.WithLockoutProtection(4, 5*time.Minute, time.Minute)
```

Four failures for one account within five minutes, and this process refuses
that account locally for a minute without asking the directory. The
directory's counter never moves.

**The ordering matters, and it is deliberate.** The cache is consulted
first, then the throttle. A user who authenticated a minute ago is served
from cache and never reaches the throttle — so somebody guessing at their
username does not lock them out of a session they already have. Without a
cache there is nothing to serve them from and they are refused along with
the attacker, which is a local cooldown of a minute rather than a directory
lockout an administrator has to clear, but it is a real cost.

**Only a refused credential counts.** A directory that was unreachable says
nothing about whether the password was right, and counting it would mean an
outage locking out everybody who tried to log in during it.

**The counters are per process and per account.** Twenty replicas pass
twenty times the threshold before all of them are blocking, and an attacker
spreading attempts across a thousand accounts is limited by nothing here.
It is not a rate limiter; put one in front.

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

## Why the directory refused

`Authenticate` returns `ErrInvalidCredentials` for every refusal —
wrong password, no such user, expired password, disabled account, locked
account, logon-hour restriction. That is not laziness. A login form that
could tell any of these apart is an account enumeration oracle; one that
could tell "password expired" from "wrong password" tells an attacker the
username is real and the account is live.

The reason is still available, on the error, for the audience that is not
the user:

```go
identity, err := auth.Authenticate(ctx, username, password)
if err != nil {
    audit.Record(username, ldapauth.ReasonFor(err))
    return unauthorized()          // the same response, whatever the reason
}
```

It comes from Active Directory's data code, always, and from the password
policy control on other directories with `WithPasswordPolicyControl()`.

**Do not put it in a response body.** Not in the message, not in an error
code, not in a header, and not in a response time — if the expired-password
path is slower than the wrong-password path, you have rebuilt the oracle
out of timing. `httpauth.WithMinimumDuration` is what flattens that.

## What this library cannot do for you

It cannot tell you whether your service account has more access than it
needs, whether your TLS certificate is verified by anything, or whether the
group whose name you put in an authorisation rule is the group you meant.
Group *names* are not unique — two subtrees can each hold a group called
`admins` — which is why `WithGroupDNs` exists and why an authorisation rule
that matters should probably use it.
