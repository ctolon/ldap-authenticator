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
| `WithDialTimeout` | one TCP connect plus TLS handshake | 5s |
| `WithOperationTimeout` | one LDAP operation on a live connection | 10s |
| `WithRequestTimeout` | one whole `Authenticate`, retries included | 15s |

The request timeout applies only when the caller's context carries no
earlier deadline. A caller who passes a deadline always gets the tighter of
the two, because they are the one who knows what the request is for.

The operation timeout is the one people forget. A server that accepts a
connection and then stops answering is a real failure mode, and without a
per-operation limit the only thing bounding it is the caller's context.

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

`WithURLs` takes an ordered list. A URL that fails to dial is moved behind
the healthy ones for `WithFailoverCooldown`, so a replica that is down
costs one connection timeout rather than one per login.

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
ldapauth.WithCacheStore(redisCache{client}),
```

The secret is what makes the sharing work: without it each replica derives
a different key for the same login, and the shared cache silently never
hits — a failure mode with no error and a large bill. See
[extending.md](extending.md) for what a store looks like, and
[security.md](security.md) for what the secret is worth to an attacker.

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
