# Contributing

## The gate

```sh
make check
```

That is format, vet, staticcheck, race tests across every module, the
dependency guard, a fuzz smoke run, and a vulnerability scan. CI runs the
same targets, so a green `make check` locally is a green CI.

For the integration suite, which needs a directory:

```sh
make integration        # brings up OpenLDAP, seeds it, runs the suite
make integration-down   # tears it down
```

Everything else — `go test ./...` included — runs with nothing installed
and nothing listening. That is deliberate: a test suite you have to
provision before it will run is a test suite people stop running.

## Dependencies

The root module has one, and adding a second needs a much better argument
than convenience. `scripts/deps-guard.sh` fails the build if the count
changes, and it runs in CI.

A framework dependency belongs in a module under `contrib/`. That is what
those modules are for: a caller who imports `ldapauth` should never find
Gin in their build graph because somebody wanted middleware.

Anything that would otherwise be a dependency should first be checked
against the standard library. `log/slog` is why logging costs nothing here,
and `Metrics` is an interface of hooks rather than a Prometheus import for
the same reason.

## Tests

Standard library `testing`, no assertion helpers, no testify. Failures read
as `got = x, want y` with the *reason* in the message:

```go
t.Fatalf("binds = %d, want 2: the service account and the user", len(binds))
```

Tests are black box (`package ldapauth_test`) unless they need something
unexported, in which case they go in `internal_test.go` with a comment
saying why the public API could not answer the question.

`t.Parallel()` at the top of every test. Time is injected with `WithClock`
rather than slept through — a test that waits for a TTL to expire is a test
that is slow on a good day and flaky on a bad one.

The in-memory directory in `ldaptest` is the fixture. It parses filters and
applies scopes for real, so a test asserting that a hostile username was
escaped is asserting something. It is also load-bearing, which is why it
has its own tests: a fake that unescaped too eagerly would report every
injection as harmless.

## The security invariants

The list is in `SECURITY.md`, and each item has a test whose name says what
it is protecting. Changing one of those tests should be hard, and should
come with an explanation. If you are here to add a feature and find one of
them in the way, that is the invariant working.

## Comments

A comment that restates the code is noise. A comment recording *why* a
decision was made is the point — why the pooled connection is never rebound
as a user, why an invalid credential is never retried, why the cache stores
a hash rather than a password. Those are the comments that stop the next
person from undoing the decision.

## Commits and pull requests

Conventional-ish subject lines: `feat:`, `fix:`, `docs:`, `test:`,
`refactor:`, `chore:`. The body explains why.

A pull request that changes behaviour changes `CHANGELOG.md` under
`## [Unreleased]`. A pull request that changes an exported signature
changes `api_test.go`, which will not compile until you do.

## Releasing

See [RELEASING.md](RELEASING.md).
