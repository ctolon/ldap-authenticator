# Extending

Seven interfaces, each with a working default. You can ignore all of them,
replace one, or replace all seven.

| | default | replace with |
|---|---|---|
| `Authenticator` | `*Client`, from `New` | anything, at your call sites |
| `Identity` | `*Principal` | `WithPrincipalMapper` |
| `PrincipalMapper` | attribute mapping | `WithPrincipalMapper` |
| `GroupResolver` | directory resolution | `WithGroupResolver` |
| `Cache` | in-memory, TTL-bounded | `WithSealedCacheStore`, or `WithCacheStore` |
| `Dialer` | TCP, TLS, StartTLS | `WithDialer` |
| `Metrics` | no-op | `WithMetrics` |

## Depend on the interface, not the type

```go
type LoginService struct {
    auth ldapauth.Authenticator   // not *ldapauth.Client
}
```

This is what lets a test substitute a fake, and what lets a deployment wrap
the real one:

```go
type breakGlass struct {
    ldapauth.Authenticator   // embed: everything else passes through

    emergency map[string]string
}

func (b breakGlass) Authenticate(ctx context.Context, username, password string) (ldapauth.Identity, error) {
    if hash, ok := b.emergency[username]; ok && verify(hash, password) {
        return &ldapauth.Principal{DN: "local:" + username, Username: username, Groups: []string{"admin"}}, nil
    }

    return b.Authenticator.Authenticate(ctx, username, password)
}
```

Embedding the interface means a method added to `Authenticator` in a later
1.x release cannot break the decorator — it passes through.

## Your own user type

`Authenticate` returns an `Identity`. `Principal` implements it, and is
what you get unless you ask for something else.

```go
type user struct {
    dn     string
    name   string
    groups []string
    tenant string
}

func (u *user) GetDN() string       { return u.dn }
func (u *user) GetUsername() string { return u.name }
// ... the rest of Identity
func (u *user) Clone() ldapauth.Identity { copy := *u; return &copy }

ldapauth.WithPrincipalMapper(ldapauth.PrincipalMapperFunc(
    func(m ldapauth.Mapping) (ldapauth.Identity, error) {
        return &user{
            dn:     m.DN,
            name:   m.Username,
            groups: m.Groups,
            tenant: m.Entry.GetAttributeValue("o"),
        }, nil
    },
))
```

`Clone` is the one method worth thinking about. The cache stores one
`Identity` and hands out copies; if yours shares a slice or a map between
clones, one caller's edit becomes every later caller's. An immutable type
can return itself.

If all you want is somewhere to hang extra data, `Principal.Extra` is
already there and needs no new type.

## Groups from somewhere else

```go
ldapauth.WithGroupResolver(ldapauth.GroupResolverFunc(
    func(ctx context.Context, r ldapauth.GroupRequest) ([]string, error) {
        return entitlements.RolesFor(ctx, r.DN)
    },
))
```

It replaces the built-in resolution rather than adding to it, so a resolver
that wants both should ask the directory itself. `GroupRequest.Search` is
there for that: a `Searcher` running on the authenticator's connection,
with the authenticator's identity, for the duration of the call. It cannot
bind, cannot write, and cannot be retained.

```go
result, err := r.Search.Search(ctx, ldap.NewSearchRequest(
    "ou=groups,dc=corp,dc=example", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
    0, 0, false, "(member="+r.DN+")", []string{"cn"}, nil,
))
```

## A shared cache

Two interfaces, and the first is almost always the one you want.

### `ByteStore` — what Redis and memcached already are

```go
type redisStore struct{ client *redis.Client }

func (s redisStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
    raw, err := s.client.Get(ctx, "ldapauth:"+key).Bytes()
    switch {
    case errors.Is(err, redis.Nil):
        return nil, false, nil
    case err != nil:
        return nil, false, err
    }

    return raw, true, nil
}

func (s redisStore) Set(ctx context.Context, key, username string, value []byte, ttl time.Duration) error {
    if err := s.client.Set(ctx, "ldapauth:"+key, value, ttl).Err(); err != nil {
        return err
    }

    // InvalidateUser has to find an account's entries without knowing the
    // password that keyed them, so keep an index.
    return s.client.SAdd(ctx, "ldapauth:user:"+strings.ToLower(username), key).Err()
}

// InvalidateUser, InvalidateAll, Len likewise.
```

```go
ldapauth.WithCache(30*time.Second),
ldapauth.WithCacheSecret(secretFromYourSecretManager),
ldapauth.WithSealedCacheStore(redisStore{client}),
```

No serialisation, no identity types, no `Principal` — the authenticator
encodes the value, seals it with `HMAC-SHA256(secret, key ‖ 0x00 ‖ value)`,
and verifies that seal on the way back. An entry that fails to verify is a
miss: logged, counted through `Metrics.CacheEvent` under `CacheError`,
and answered by asking the directory.

It does not carry `Principal.Extra`, and it cannot encode a custom
`Identity` from `WithPrincipalMapper` — the write fails, is counted, and the
login proceeds uncached. That is when the second interface exists.

### `Cache` — when the encoding has to be yours

```go
type redisCache struct{ client *redis.Client }

func (c redisCache) Get(ctx context.Context, key string) (ldapauth.Identity, bool, error) {
    raw, err := c.client.Get(ctx, "ldapauth:"+key).Bytes()
    switch {
    case errors.Is(err, redis.Nil):
        return nil, false, nil
    case err != nil:
        return nil, false, err
    }

    if len(raw) == 0 {
        return nil, true, nil   // a cached rejection
    }

    var p ldapauth.Principal
    if err := json.Unmarshal(raw, &p); err != nil {
        return nil, false, err
    }

    return &p, true, nil
}

// Set, InvalidateUser, InvalidateAll, Len likewise.
```

Four things to know.

**Nothing authenticates the value.** The authenticator is handed a decoded
`Identity` and believes it. The key is an HMAC, so nobody without the secret
can address a particular login — but anybody who can *write* to the store
can put an identity carrying whatever groups they like under a key of their
choosing, and the login that lands on it is authorised as that. If you use
this interface against a shared store, write access to that store is
equivalent to write access to the directory. Say so in your threat model.
[`examples/sealed-cache`](../examples/sealed-cache) demonstrates both sides
of this in about a screen of output.

**Keys are opaque and the store never sees a credential.** The key is a
hex-encoded HMAC of the username and password under the authenticator's
secret: printable, fixed length, and a valid memcached key with no encoding
of your own.

**A shared cache needs a shared secret.** By default the secret is drawn
from the system CSPRNG at startup, so every replica derives a different key
for the same login and the shared cache never hits. `WithCacheSecret` fixes
that, and the value is a secret: anybody holding it can test a guessed
credential against the cache offline.

**A cache that is down must not be a directory that is down.** Every method
may return an error, and the authenticator treats one as a miss: it logs
it, counts it, and asks the directory.

The last thing to think about is the trust boundary. A cache shared between
two services is a cache in which one service's authentication decisions
become the other's.

## A different transport

```go
ldapauth.WithDialer(myDialer{})   // returns an ldapauth.Conn
```

`Conn` is five methods, all of which `*ldap.Conn` already has. Implement it
to reach a directory through something this package cannot dial — an SSH
tunnel, a service mesh sidecar — or to drive failure paths in a test, which
is what `ldaptest` does.

A custom dialer takes over responsibility for TLS: the TLS options are not
applied to it, and the plaintext check in `New` is skipped, because there
is no way for this package to know what your dialer negotiated.

## Swapping the whole client

The service account password is read once, at construction. To rotate it,
build a new `Client` and swap the pointer:

```go
auth := ldapauth.NewReloadable(client)   // implements Authenticator

// later
next, err := ldapauth.New(optionsWith(newPassword)...)
if err != nil {
    return err                  // a failed reload keeps the working client
}

previous := auth.Replace(next)
previous.Close()
```

`Replace` returns the old `Client` rather than closing it, because when to
close it is your decision — immediately for a password rotation, after a
grace period if something outside this package still holds a reference.

The ordering is the part that is easy to get wrong: close the old one
*after* the swap. Closing it does not interrupt requests already running on
it, and by the time you call Close nothing new is choosing it.
[`examples/reloading`](../examples/reloading) does it under load and counts
the failures; there are none.

## Metrics

```go
type promMetrics struct {
    ldapauth.NoopMetrics   // embed, so later interface methods do not break you

    attempts *prometheus.CounterVec
}

func (m *promMetrics) AuthAttempt(result string, d time.Duration) {
    m.attempts.WithLabelValues(result).Inc()
}
```

`Metrics` is frozen for the 1.x line. No method will be added to it —
adding one would break every implementation that did not happen to embed
`NoopMetrics`, and "embed this and hope" is a request rather than a
compatibility promise. Anything worth counting later arrives as a separate
optional interface, discovered by type assertion, which an implementation
may satisfy or ignore.

Embedding `NoopMetrics` is still worth doing: it saves writing the methods
you do not care about.

Every method is called on the goroutine doing the work, so an
implementation that blocks blocks an authentication. Do the cheap thing and
buffer if you must.
