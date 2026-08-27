# Configuration reference

Every option, what it defaults to, and the one thing worth knowing about
it. The doc comments in the package say more; this is the map.

Options are applied in order and validated as they are applied, so `New`
reports a bad value with the name of the option that carried it — at
startup, rather than as a mysterious failure on the first login.

## Servers and transport

| option | default | note |
|---|---|---|
| `WithURL(url)` | — | required; appends, so it composes with `WithURLs` |
| `WithURLs(urls...)` | — | tried in order; see [production.md](production.md) |
| `WithDialer(d)` | built from the TLS options | takes over responsibility for TLS |
| `WithDialTimeout(d)` | 5s | one TCP connect plus handshake; zero is an error |
| `WithOperationTimeout(d)` | 10s | one LDAP operation; the one people forget |
| `WithRequestTimeout(d)` | 15s | one whole call, retries included; the caller's deadline wins when tighter |
| `WithFailoverPolicy(p)` | `FailoverInOrder` | `FailoverRoundRobin`, `FailoverRandom` |
| `WithFailoverCooldown(d)` | 30s | how long a failed URL is tried last; never removed |

## TLS

| option | default | note |
|---|---|---|
| `WithTLSConfig(t)` | — | replaces anything the narrower options set; cloned |
| `WithStartTLS()` | off | upgrades `ldap://`; a refused upgrade is a hard failure |
| `WithRootCAs(pool)` | system pool | |
| `WithRootCAFile(path)` | system pool | read once, at option time |
| `WithClientCertificate(cert)` | — | mutual TLS |
| `WithClientCertificateFiles(cert, key)` | — | read once; rotate with `GetClientCertificate` via `WithTLSConfig` |
| `WithServerName(name)` | from the URL | for connecting by IP, or through another name |
| `WithMinTLSVersion(v)` | TLS 1.2 | 1.0 and 1.1 are refused outright |
| `WithInsecureSkipVerify()` | off | encryption without authentication; lab only |
| `WithInsecureNoTLS()` | off | permits plaintext; named to be ugly on purpose |

`New` refuses a plaintext `ldap://` URL unless StartTLS is configured or
`WithInsecureNoTLS` is passed. `ldapi://` unix sockets are exempt.

## Bind strategy

Exactly one of these two. See [strategies.md](strategies.md).

| option | default | note |
|---|---|---|
| `WithDirectBind(template)` | — | `uid={{username}},ou=people,...`; `%s` also accepted |
| `WithUserSearch(baseDN, filter)` | — | needs a service account |
| `WithUserSearchScope(scope)` | whole subtree | `ScopeBaseObject`, `ScopeSingleLevel` |
| `WithDerefAliases(deref)` | never | an alias that redirects a search redirects an authentication |
| `WithSearchSizeLimit(n)` | server's | |
| `WithPagingSize(n)` | off | Active Directory truncates at 1000 and says nothing |
| `WithServiceAccount(dn, password)` | — | needs read, never write, never `userPassword` |
| `WithAnonymousServiceBind()` | off | must be asked for explicitly |
| `WithReferralPolicy(p)` | `ReferralIgnore` | `ReferralFail` turns a referral-only answer into an error |
| `WithPasswordPolicyControl()` | off | how a non-AD directory says *why* it refused |

## Attributes

| option | default | note |
|---|---|---|
| `WithUsernameAttribute(name)` | the supplied username | |
| `WithDisplayNameAttribute(name)` | — | commonly `displayName` or `cn` |
| `WithEmailAttribute(name)` | — | commonly `mail` or `userPrincipalName` |
| `WithAttributes(names...)` | — | appends; ask only for what you use |

Nothing is fetched unless something asks for it. An attribute you fetch is
an attribute you may accidentally log.

## Groups

Off by default. See [groups.md](groups.md).

| option | default | note |
|---|---|---|
| `WithMemberOfGroups()` | off | free; needs the attribute to exist |
| `WithMemberOfAttribute(name)` | `memberOf` | also selects the memberOf source |
| `WithGroupSearch(baseDN, filter)` | off | one search per level; works anywhere |
| `WithActiveDirectoryGroups(baseDN)` | off | one search, transitive; AD only |
| `WithGroupSearchScope(scope)` | whole subtree | |
| `WithGroupNameAttribute(name)` | `cn` | |
| `WithGroupDNs()` | names | names are not unique; DNs are |
| `WithNestedGroups()` | off | bounded by depth *and* a visited set |
| `WithNestedGroupDepth(n)` | 4 | implies `WithNestedGroups` |
| `WithGroupResolver(r)` | directory resolution | replaces it; see [extending.md](extending.md) |

## Connection pool

Only built when the configuration searches the directory. See
[production.md](production.md).

| option | default | note |
|---|---|---|
| `WithPoolSize(n)` | 10 | size against the directory's limit, not your request rate |
| `WithPoolMinIdle(n)` | 0 | warmed in the background at startup |
| `WithPoolMaxLifetime(d)` | 30m | keep it finite, and under any load balancer's idle timeout |
| `WithPoolMaxIdleTime(d)` | 5m | |
| `WithPoolHealthCheck(on)` | on | a Who Am I before hand-out; off trades a round trip for a retry |

## Retry

| option | default | note |
|---|---|---|
| `WithRetry(n)` | 2 | retries, over and above the first attempt |
| `WithoutRetry()` | — | |
| `WithRetryBackoff(base, max, multiplier)` | 50ms, 2s, 2.0 | full jitter |
| `WithRetryMaxElapsed(d)` | 10s | a retry that would sleep past the cap is not taken |

A rejected credential is **never** retried, whatever these say. Directories
with a lockout policy count failed binds.

## Cache

Off by default. See [production.md](production.md) and
[security.md](security.md).

| option | default | note |
|---|---|---|
| `WithCache(ttl)` | off | capped at `MaxCacheTTL`, five minutes |
| `WithNegativeCache(ttl)` | 5s | stops a stale password reaching a lockout policy |
| `WithCacheSize(n)` | 4096 | |
| `WithSealedCacheStore(s)` | in-memory | for a cache shared between replicas; values are sealed and verified |
| `WithCacheStore(c)` | in-memory | the lower-level form; the value is **not** authenticated |
| `WithCacheSecret(b)` | random per process | required for a shared cache; is itself a credential |
| `WithCacheUsernameHashing()` | off | the store sees a hash instead of the username |

## Input handling

| option | default | note |
|---|---|---|
| `WithUsernameMaxLength(n)` | 256 | rejected before any network call |
| `WithPasswordMaxLength(n)` | 1024 | not about strength; about not carrying a megabyte |
| `WithCaseFoldUsername()` | off | changes the cache key only, never what is sent |
| `WithUsernameRedaction()` | off | `[redacted]` in logs and errors |
| `WithLockoutProtection(n, window, cooldown)` | off | refuses locally so the directory's lockout counter never moves |

## Behaviour

| option | default | note |
|---|---|---|
| `WithPrincipalMapper(m)` | attribute mapping into `Principal` | your own user type |
| `WithGroupResolver(r)` | directory resolution | groups from elsewhere |

## Observability

| option | default | note |
|---|---|---|
| `WithLogger(l)` | discards | `*slog.Logger`; never sees a password |
| `WithMetrics(m)` | no-op | embed `NoopMetrics` in yours |
| `WithClock(now)` | `time.Now` | for tests; must be safe for concurrent use |

## Reading a failure

Everything a refusal knows, without changing what the caller is told.

```go
var authErr *ldapauth.AuthError
if errors.As(err, &authErr) {
    authErr.Op          // "bind", "user search", "group search", "throttle", "cache"
    authErr.URL         // the server it was talking to
    authErr.ResultCode  // the LDAP result code
    authErr.Reason      // why the directory refused, when it said
    authErr.Referrals   // where it said to look instead
}

ldapauth.ReasonFor(err)     // the reason without the type assertion
```

`RejectionReason` is a closed set — `ReasonBadPassword`,
`ReasonPasswordExpired`, `ReasonAccountDisabled`, `ReasonAccountLocked`,
`ReasonAccountExpired`, `ReasonPasswordMustChange`, `ReasonTimeRestricted`,
`ReasonWorkstationRestricted`, `ReasonNoSuchUser`, `ReasonUnspecified` —
so it is safe as a metrics label. `Actionable()` reports whether trying
again with different credentials could help, which is the distinction a
help desk cares about.

## Rotating without a restart

```go
auth := ldapauth.NewReloadable(client)

previous := auth.Replace(next)
previous.Close()
```

`*Reloadable` implements `Authenticator`, so everything downstream is
unaffected. See [production.md](production.md).

## Exported defaults

Every default has a name, because a default you cannot name is a default
you cannot reason about — `DefaultDialTimeout`, `DefaultPoolSize`,
`MaxCacheTTL`, and the rest. A deployment that wants "the library default,
but doubled" can write that down.
