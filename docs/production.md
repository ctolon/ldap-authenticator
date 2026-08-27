# Running this in production

## A configuration to start from

```go
auth, err := ldapauth.New(
    ldapauth.WithURLs(
        "ldaps://dc1.corp.example:636",
        "ldaps://dc2.corp.example:636",
    ),
    ldapauth.WithRootCAFile("/etc/ssl/certs/corp-ca.pem"),

    ldapauth.WithServiceAccount("cn=readonly,dc=corp,dc=example", os.Getenv("LDAP_SERVICE_PASSWORD")),
    ldapauth.WithUserSearch("ou=people,dc=corp,dc=example", "(uid={{username}})"),
    ldapauth.WithMemberOfGroups(),
    ldapauth.WithEmailAttribute("mail"),

    ldapauth.WithDialTimeout(3*time.Second),
    ldapauth.WithOperationTimeout(5*time.Second),
    ldapauth.WithRequestTimeout(10*time.Second),

    ldapauth.WithPoolSize(16),
    ldapauth.WithPoolMinIdle(2),
    ldapauth.WithPoolMaxLifetime(30*time.Minute),

    ldapauth.WithRetry(2),
    ldapauth.WithLogger(slog.Default()),
    ldapauth.WithMetrics(metrics),
)
```

Build it once at startup and share it. It is safe for concurrent use, and
it owns the pool.

## Timeouts

Three, and they nest:

| | bounds | default |
|---|---|---|
| `WithDialTimeout` | one TCP connect, plus the TLS handshake or StartTLS upgrade | 5s |
| `WithOperationTimeout` | one LDAP operation on a live connection | 10s |
| `WithRequestTimeout` | one whole `Authenticate`, retries included | 15s |

The request timeout applies only when the caller's context carries no
earlier deadline. A caller who passes a deadline always gets the tighter of
the two, because they are the one who knows what the request is for.

The operation timeout is the one people forget. A server that accepts a
connection and then stops answering is a real failure mode, and without a
per-operation limit the only thing bounding it is the caller's context.

The dial timeout covers a StartTLS upgrade as well as the connect, which
matters more than it sounds: the upgrade is a round trip and then a TLS
handshake, and neither is bounded by the TCP connect timeout. A server that
accepts a connection and goes silent during the upgrade is refused at the
dial timeout and its connection closed, rather than left to something else
to notice.

Set the request timeout below whatever your HTTP server's write timeout is.
A login that outlives the response it was for is a goroutine holding a pool
slot for nothing.

## The pool

The pool holds service-account connections. Under direct bind with no
service account there is no pool at all.

Size it against the directory's connection limit rather than against your
request rate: pooled connections are held for the duration of a search,
which is milliseconds. Sixteen is a lot for most deployments.

- `WithPoolMinIdle` keeps connections open and bound so that a burst after
  a quiet period does not pay for a fresh bind each time.
- `WithPoolMaxLifetime` retires a connection however healthy it is. Keep it
  finite and well under any idle timeout enforced by the directory or a
  load balancer in front of it. A connection that never retires never
  notices that the load balancer has new backends.
- `WithPoolHealthCheck` probes with a Who Am I before hand-out. That is a
  round trip; without it, the first search on a connection the server
  quietly dropped fails instead and is retried on a fresh one. Leave it on
  unless the directory is local and the request rate is high.

## Failover

`WithURLs` takes an ordered list. A URL that fails is moved behind the
healthy ones for `WithFailoverCooldown`, so a replica that is down costs
one connection timeout rather than one per login.

**Failing is not only failing to dial.** A server that accepts a TCP
connection, completes a TLS handshake, and then cannot take a bind or
answer a search is out of service just as thoroughly as one that refuses
the connection — and it is the more common shape, because that is what a
directory looks like while it is shutting down, out of file descriptors, or
returning `unavailable`. Those failures start the cooldown too.

A rejected credential does not. A wrong password says nothing about the
server, and penalising on one would let a user with a typo take a healthy
replica out of rotation.

The cooldown reorders; it never removes. Every URL is still tried before a
call fails, so a cooldown cannot turn a slow directory into an outage.

`FailoverInOrder` is the default and is right when the list is ordered by
preference — a local replica first, a remote one behind it. Use
`FailoverRoundRobin` or `FailoverRandom` when the servers are equivalent
and you would rather not send every bind in the fleet to the same replica.

Failover is between servers holding the same data. It is not a way to
authenticate against several unrelated directories: whichever server
answers, the same base DNs and filters are used against it.

## Retry

Two retries by default, with full-jitter exponential backoff, and only for
failures that say nothing about the answer: a broken connection, a busy
server, a server going down.

A rejected credential is never retried. Directories with a lockout policy
count failed binds, and a library that retried them would turn one typo
into three strikes.

## Caching

Leave it off unless something in front of this package re-authenticates the
same credentials faster than the directory can absorb — HTTP Basic auth on
a chatty API being the usual reason.

```go
ldapauth.WithCache(30*time.Second),
ldapauth.WithNegativeCache(5*time.Second),
ldapauth.WithCacheSize(4096),
```

What it costs is a window in which a disabled account still works.
`MaxCacheTTL` caps it at five minutes. `InvalidateUser` drops an account's
entries early, for when you have just changed somebody's password.

The negative cache is worth having even at a short TTL: it stops a
misconfigured client looping on a stale password from reaching the
directory often enough to lock the account out.

## Several replicas

Nothing is shared between processes unless you share it. Each replica has
its own pool, its own failover state, and its own cache secret — which
means, by default, its own cache.

To share one:

```go
ldapauth.WithCache(30*time.Second),
ldapauth.WithCacheSecret(secretFromYourSecretManager),
ldapauth.WithSealedCacheStore(redisStore{client}),
```

The secret is what makes the sharing work: without it each replica derives
a different key for the same login, and the shared cache silently never
hits — a failure mode with no error and a large bill.

`WithSealedCacheStore` takes a `ByteStore` — a Get, a Set, and two
invalidations over `[]byte`, which is what Redis and memcached already are.
The authenticator serialises the identity and seals it under the same
secret, and verifies the seal on the way out, so an entry that somebody
else wrote is a miss rather than an authorisation. Use the older
`WithCacheStore` only when you need your own encoding; the difference and
why it matters is in [security.md](security.md). See
[extending.md](extending.md) for what a store looks like.

Two more things matter at fleet scale:

- **Retry backoff is fully jittered**, so a fleet that lost its directory
  at the same instant does not come back at the same instant.
- **`FailoverInOrder` sends every replica to the same server first.** That
  is usually right — the list is ordered by preference. When the servers
  are equivalent and you would rather spread the load,
  `FailoverRoundRobin` or `FailoverRandom`; prefer random when many
  processes start together, because their round robins would otherwise
  march in step.

Within one process, identical logins arriving at once are collapsed into a
single round trip. That is the part of a stampede the cache cannot absorb,
since the cache only helps once the first attempt has finished.

## Health checks

```go
if err := auth.HealthCheck(ctx); err != nil {
    // not ready
}
```

Wire it to a **readiness** probe, not a liveness probe. A directory that is
down is a reason to stop taking traffic, not a reason to restart the
process — restarting throws away a warm pool and does nothing about the
directory.

## What to alert on

`Metrics` gives you the raw material. The signals worth watching:

- **`AuthAttempt` with `error`** — the directory is not answering. This is
  the page.
- **`AuthAttempt` with `invalid_credentials`, as a rate** — a step change
  is either an outage in something upstream or somebody guessing.
- **`ConnClosed` with `unhealthy`, as a rate** — connections are dying
  between checkout and use. Usually an idle timeout somewhere in the path
  that is shorter than `WithPoolMaxLifetime`.
- **`PoolStats` in-use at the configured size** — requests are queuing on
  pool slots. Either the pool is too small or the directory has become
  slow.
- **`RetryScheduled`, as a rate** — the transport is unreliable. Retries
  are hiding it from your users, which is what they are for, but the
  underlying problem is still there.
- **`Stats(ctx).HealthyServers` below `Stats(ctx).Servers`** — failover is
  in use. Worth a ticket even though nothing is failing.
- **`CacheEvent` with `error`** — the cache is not answering. Nothing is
  failing yet, because a cache that is down falls through to the
  directory, but the directory is now taking the load the cache was there
  to absorb.

## The layers around it

At any scale worth calling scale, this package is the third layer down:

```text
application
  ↓  rate limiter        per client — yours
  ↓  circuit breaker     per directory — yours
  ↓  ldap-authenticator  lockout protection, cache, coalescing, retry, failover
  ↓  LDAP
```

Both outer layers are decorators over `ldapauth.Authenticator`, which is
why that interface exists. [`examples/layered`](../examples/layered) is a
working one of each, about sixty lines together.

Neither belongs in the library, and the reason is the same for both: their
policy is about your traffic rather than about your directory. A rate
limiter's bucket is per IP or per session or per API key, with your
thresholds and your idea of what to do when it trips. A breaker's
thresholds are about your request volume. Every deployment already has an
opinion and usually a library.

**The breaker earns its place when the directory is completely down.**
Without one, every request pays the whole chain — dial timeout, failover to
the next URL, another dial timeout, retries with backoff — before failing.
That is seconds of held goroutines per request, and under load it is how a
directory outage becomes an application outage. With one, the first few
requests pay it and the rest fail immediately.

One thing to get right in a breaker over this package: **a rejected
credential is a working directory.** Count only the failures that say the
directory is unwell, or the first user to mistype their password opens the
breaker for everybody.

## Protecting the directory's lockout policy

```go
ldapauth.WithLockoutProtection(4, 5*time.Minute, time.Minute)
```

A directory that locks an account after five failures is a directory where
anybody who knows a username can lock that account out — from anywhere, no
access needed, and the victim is the one who calls the help desk. This
package already refuses to make it worse by retrying a rejected credential.
This stops it being the instrument: after four failures in five minutes,
the account is refused locally for a minute and the attempts never reach
the directory.

Three things to know before turning it on.

**It refuses the real user too.** That is the cost, and it is why this is
not the default. With `WithCache` on, a user who logged in recently is
served from cache and never reaches the throttle, which buys most of it
back — see the ordering in [security.md](security.md).

**It is per process.** Twenty replicas pass twenty times the threshold
before all of them are blocking. Making it exact would mean a round trip to
somewhere shared on every failed login, paid on the attack path.

**It is not a rate limiter.** It counts failures per account, not requests
per client. An attacker spreading attempts across a thousand accounts is
limited by nothing here.

Watch `Stats(ctx).BlockedAccounts`. A number that climbs is either an
attack or a client with a stale credential, and both are worth a look.

## Rotating the service account password

The password is read once, when the Client is built. Rotating it means
building a new Client and swapping the pointer, and
[`ldapauth.Reloadable`](extending.md) is that:

```go
auth := ldapauth.NewReloadable(client)

// when the secret manager says the password changed
next, err := ldapauth.New(optionsWith(newPassword)...)
if err != nil {
    return err          // keep serving with the old one
}

previous := auth.Replace(next)
previous.Close()
```

The ordering is the part people get wrong: close the old Client *after* the
swap, never before. Closing it does not interrupt requests already running
on it — they finish against connections closed as they are released — and
by the time you call Close, nothing new is choosing it.

[`examples/reloading`](../examples/reloading) does this under load and
counts the failures. There are none.

### What the new Client does not inherit

It inherits nothing. A Client's state lives in the Client, so the
replacement starts with an empty cache, an empty throttle, and — unless you
passed `WithCacheSecret` — a freshly generated cache secret that makes every
existing key underivable.

Rotating hourly therefore means an empty cache hourly, and a throttle whose
count of recent failures resets with it: somebody who can time a rotation
gets another `WithLockoutProtection` allowance on the far side of it.

So build the replacement from the same option list as the original with only
the credential changed, and in particular carry these across:

```go
func optionsWith(password string) []ldapauth.Option {
    return []ldapauth.Option{
        // ... everything else, unchanged ...
        ldapauth.WithCache(30 * time.Second),
        ldapauth.WithCacheSecret(cacheSecret),          // same secret, every time
        ldapauth.WithSealedCacheStore(sharedStore),     // same store, every time
        ldapauth.WithServiceAccount(bindDN, password),  // the only thing that moved
    }
}
```

With a shared store and a fixed secret the cache survives a rotation
entirely, because the entries were never in the process. The throttle is
per-process either way; if you rotate often enough for the reset to matter,
rate limit in front — [`examples/layered`](../examples/layered) shows the
shape.

## Cache invalidation across replicas

`InvalidateUser` empties the cache it is given. Which cache that is
decides how far it reaches:

| | `InvalidateUser` reaches | when an account is disabled |
|---|---|---|
| No cache | nothing to reach | takes effect immediately |
| Local cache, one replica | that replica | immediate |
| Local cache, twenty replicas | **the replica you called** | up to the TTL on the other nineteen |
| Shared cache (`WithCacheStore`) | every replica | immediate |

The third row is the one that bites. With local caches and twenty pods,
disabling an account leaves nineteen of them still letting that account in
until their TTLs expire — and there is no way for one pod to tell the
others, short of you building the fan-out.

Two answers, and they are both fine:

- **Share the cache.** `WithSealedCacheStore` plus `WithCacheSecret`, and
  invalidation is immediate everywhere. Prefer the sealed form over
  `WithCacheStore`: a shared store is a store somebody else can write to,
  and [security.md](security.md) explains what that buys them if the value
  is not authenticated.
- **Keep the TTL short enough that you do not care.** Thirty seconds of a
  disabled account still working is a different conversation from an hour
  of it. `MaxCacheTTL` caps it at five minutes regardless.

What this package will not do is build a distributed invalidation channel.
That is a message bus, and a library that shipped one would be a library
with a message bus in it.

## What this library does not do for you

Worth stating plainly, because each of these is a thing an operator has to
own and none of them has an option here that would suggest otherwise.

**TLS to your users.** This package encrypts the connection to the
directory. Whatever carries the password from a browser to your process is
your HTTP server's business, and Basic auth over plaintext HTTP puts it on
the wire in the clear no matter how carefully this package handles it
afterwards.

**Rate limiting.** `WithLockoutProtection` counts failures per *account*,
which protects the directory's lockout policy. It does not count requests
per client, which is what stops brute force, and the two are different
questions. Put a rate limiter in front; see the layering above.

**Authorisation.** `Principal.Groups` is a list of names, or of DNs under
`WithGroupDNs`. Deciding what a group is allowed to do is yours, and group
*names* are not unique — two subtrees can each hold a `cn=admins`. If a
rule matters, write it against a DN.

**Secret rotation.** The mechanism is here —
[`ldapauth.Reloadable`](extending.md) — but noticing that a secret changed
is not. Watch the file, poll the secret manager, subscribe to whatever your
platform offers, and call `Replace`. Client certificates are the same,
unless you set `GetClientCertificate` through `WithTLSConfig`, which
rotates them without a swap.

**Rollback.** A Go module version is immutable once the proxy has seen it.
Rolling back means pinning the previous version in your own `go.mod`, and
that is worth having rehearsed before you need it: `go get
github.com/ctolon/ldap-authenticator@v1.0.0`, rebuild, redeploy. Nothing in
this package's state outlives a process, so there is no migration to undo.

## Secrets

The service account password is a secret. Read it from the environment or a
secret manager; do not put it in a configuration file that ends up in the
repository. This package never logs it, and it never appears in an error.

Rotating it means building a new authenticator. That is a deliberate
non-feature: an authenticator whose credentials can change underneath it is
an authenticator with a lock around every field.

## TLS

`ldaps://` or StartTLS. `New` refuses plaintext unless you pass
`WithInsecureNoTLS`, and the option is named that way so a reviewer
grepping for `Insecure` finds it.

`WithInsecureSkipVerify` turns TLS into encryption without authentication:
anybody who can answer for the directory's address can present their own
certificate and take the bind. Use `WithRootCAFile` instead, including
against an internal CA.

For mutual TLS, `WithClientCertificateFiles` reads the pair once at
startup. To rotate without a restart, set `GetClientCertificate` through
`WithTLSConfig`.
