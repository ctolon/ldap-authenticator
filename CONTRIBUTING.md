# Contributing

## The gate

```sh
make check
```

That is format, vet, staticcheck, the documentation checks, race tests
across every module, cross-compilation for sixteen platforms, the
dependency guard, coverage against its floor, a fuzz smoke run over every
target, a vulnerability scan, and a lint of the workflows. CI runs the same
targets, so a green `make check` locally is a green CI — the one thing it
adds is running the tests on macOS and Windows as well.

It takes a few minutes, mostly fuzzing. `make test-race` is the fast loop.

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

Prefer a property over a table. A fuzz target that asserts "no username
authenticates as somebody it is not" survives an attack nobody thought of;
a table of known-bad inputs only survives the ones somebody did. New
targets are discovered automatically by `scripts/fuzz.sh`, so adding one is
adding a function.

Nothing in the package may reimplement something go-ldap or the standard
library already does. The escaping is go-ldap's, scope validation asks
go-ldap which scopes exist, the Fiber adapter hands its Basic header to
net/http's parser. A second implementation is a second thing to keep
correct, and the fuzz targets assert the property rather than the
implementation, so they keep working whoever provides it.

## The security invariants

The list is in `SECURITY.md`, and each item has a test whose name says what
it is protecting. Changing one of those tests should be hard, and should
come with an explanation. If you are here to add a feature and find one of
them in the way, that is the invariant working.

## Documentation

Two checks, both in `make check`:

- **`make doc-check`** fails if an exported declaration has no doc comment.
  staticcheck checks that a comment is *shaped* right; nothing in the
  toolchain checks that one exists. For a library the exported surface is
  the documentation, and a symbol somebody has to read the implementation
  to use is a symbol that is not finished.
- **`make docs-check`** fails if the markdown and the repository have
  drifted: a doc nothing links to, a link to a file that was renamed, an
  example directory nobody mentions, a module with no README.

A comment that restates the code is noise. A comment recording *why* a
decision was made is the point — why the pooled connection is never rebound
as a user, why an invalid credential is never retried, why the cache stores
a hash rather than a password. Those are the comments that stop the next
person from undoing the decision.

An option's doc comment should say what it costs, not only what it does.
"Probes with a Who Am I before hand-out; that is a round trip, and without
it the first search on a dropped connection fails instead" is useful.
"Enables the pool health check" is not.

## Examples

Every example runs against the in-memory directory unless a real URL is a
flag, so `go run ./examples/...` works on a laptop with nothing installed.
An example that needs a server is an example nobody runs.

A new example goes in the README's table — `make docs-check` will remind
you.

## Commits and pull requests

Conventional-ish subject lines: `feat:`, `fix:`, `docs:`, `test:`,
`refactor:`, `chore:`. The body explains why.

A pull request that changes behaviour changes `CHANGELOG.md` under
`## [Unreleased]`. A pull request that changes an exported signature
changes `api_test.go`, which will not compile until you do.

## Releasing

See [RELEASING.md](RELEASING.md).
