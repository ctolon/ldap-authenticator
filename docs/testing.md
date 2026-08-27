# Testing

## The in-memory directory

`ldaptest` is a directory that lives in a map. It parses filters, applies
scopes, and models bind semantics faithfully, so a test written against it
is testing something.

```go
dir := ldaptest.New(
    ldaptest.User("uid=alice,ou=people,dc=example,dc=com", "s3cret").
        With("uid", "alice").
        With("objectClass", "inetOrgPerson").
        With("memberOf", "cn=devs,ou=groups,dc=example,dc=com"),

    ldaptest.Group("cn=devs,ou=groups,dc=example,dc=com").
        With("cn", "devs"),
)

auth, err := ldapauth.New(
    ldapauth.WithURL("ldap://in-memory"),
    ldapauth.WithDialer(dir.Dialer()),
    ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),
    ldapauth.WithMemberOfGroups(),
)
```

Nothing listens on a socket. The dialer hands out connections that talk to
the map directly.

### What it will tell you

```go
dir.Binds()      // every bind, in order, with the password it carried
dir.Filters()    // every search filter, as it went out
dir.Searches()   // the full search requests
dir.Conns()      // how many connections were opened and closed
```

`Binds()` records the password on purpose: the point of recording it is to
let a test assert that an empty one was never sent.

### Making things go wrong

```go
dir.SetDown("ldap://dc1", true)                    // dial fails; live connections break
dir.DialHook = func(url string) error { ... }      // fail, count, or delay a dial
dir.BindHook = func(dn, password string) error { ... }
dir.SearchHook = func(r *ldap.SearchRequest) error { ... }
```

`SetDown` also breaks connections that were already open, which is what a
server going down actually does and what a pool has to survive.

### Time

```go
clock := &myClock{now: time.Now()}
ldapauth.WithClock(clock.Now)
```

Cache expiry, failover cooldowns, and connection lifetimes are all decided
against this clock. Advance it rather than sleeping — a test that waits for
a TTL is slow on a good day and flaky on a bad one.

### What it is not

It is not a server, and it is not a validator. It will not check schemas,
enforce ACLs, or complain about an entry with no `objectClass`. Those are
exactly the differences that make something work in tests and fail in
production, which is what the integration suite is for.

## The integration suite

```sh
make integration        # up, seed, run
make integration-down   # tear down
```

`integration/` runs against a real OpenLDAP in a container. Every test
there skips unless a URL is given, with `-ldap-url` or `LDAPAUTH_TEST_URL`,
so `go test ./...` stays fast and green on a laptop with nothing running.

What it covers is what a fake cannot answer: that a real directory accepts
the filters and DNs this library builds, that its result codes classify the
way the retry logic assumes, and that a bind with an empty password behaves
the way the specification says.

The fixture is in `integration/ldifs/`, and it is deliberately awkward: one
of the users has a comma in their CN, so that DN escaping is exercised
against a server's own parser rather than against ours.

`integration/config/00-acl.ldif` replaces the image's default ACLs with the
least-privilege ones this library's documentation recommends — a service
account that can read the tree, cannot write, and cannot read
`userPassword`. Without it the container hides the tree from everything but
the admin account, and every search comes back as "no such object".

## Fuzzing

Four targets, all in `fuzz_test.go`:

| | asserts |
|---|---|
| `FuzzEscapeFilterValue` | the output carries no unescaped filter structure |
| `FuzzEscapeDNValue` | the DN parses back to exactly the components the template had |
| `FuzzParseTemplate` | template parsing is total, and expansion is deterministic |
| `FuzzCheckUsername` | whatever is accepted is safe to splice |

They assert properties rather than outputs, which is the difference between
a fuzz target and a slow table test.

```sh
make fuzz-smoke                                    # 30s each, as CI does
go test -run '^$' -fuzz FuzzEscapeDNValue -fuzztime 5m .
```

A crasher goes in `testdata/fuzz/`, which is deliberately not gitignored: a
crasher committed alongside its fix is the only artefact that proves the
fix was tested against the thing it fixes.

## Testing your own code

Your handlers should not need a directory at all. Put a principal in the
context directly:

```go
ctx := httpauth.WithPrincipal(r.Context(), &ldapauth.Principal{
    DN:       "uid=alice,ou=people,dc=example,dc=com",
    Username: "alice",
    Groups:   []string{"developers"},
})
```

Save `ldaptest` for testing the authentication itself.
