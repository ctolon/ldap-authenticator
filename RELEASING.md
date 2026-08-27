# Releasing

The branch model is `dev` → `main`. The tag is the release.

## The order matters

This repository holds four modules. The three under `contrib/` require the
root module at the version they are released alongside, so **the root tag
has to exist and be visible to the module proxy before the contrib tags are
pushed**. Doing it the other way round publishes contrib modules that
cannot be fetched.

```
v0.1.0                  root module, and httpauth and ldaptest with it
contrib/gin/v0.1.0      after the root tag is indexed
contrib/echo/v0.1.0
contrib/fiber/v0.1.0
```

## Cutting a release

```sh
./scripts/release.sh patch     # or minor, major, or an explicit X.Y.Z
```

The script refuses a dirty tree, the wrong branch, a tag that already
exists, and an empty `## [Unreleased]` section. It runs `make check`,
rotates the changelog, commits, and annotates the tag.

**It pushes nothing.** Pushing is a separate, deliberate act:

```sh
git push origin main
git push origin v0.1.0
```

Then, once <https://proxy.golang.org/github.com/ctolon/ldap-authenticator/@v/list>
lists the new version:

```sh
./scripts/release.sh --contrib 0.1.0
git push origin contrib/gin/v0.1.0 contrib/echo/v0.1.0 contrib/fiber/v0.1.0
```

## What the workflow checks before publishing

| Check | Why |
|---|---|
| The tag is an ancestor of `main` | A release built from a branch nobody merged is a release nobody reviewed |
| `make check` at the tagged commit | The gate ran against exactly what is being published, not against what was on the developer's disk |
| The changelog has a section for the version | A release with no notes is a release nobody can decide whether to take |
| The root module still has one direct dependency | The claim on the front of the README |
| The proxy indexes the module | A tag the proxy cannot see is a release nobody can install |

## The replace directives

Each contrib `go.mod` carries `replace github.com/ctolon/ldap-authenticator
=> ../..`, so that the modules build in a checkout before the root tag
exists. A replace directive in a dependency is ignored by whoever imports
it, so this affects nothing downstream.

It does mean a contrib module is never built against the *published* root
module during development. CI closes that gap: once a release exists, the
release workflow drops the replace and builds each contrib module against
the version it requires. If that fails, the require line is wrong.

## Versioning

Semantic versioning. Before 1.0, a minor bump may break the API and will
say so in the changelog under `### Breaking`.

Go's rules to keep in mind:

- A tag is immutable once the proxy has seen it. There is no fixing a bad
  release, only releasing another one.
- Major version 2 and beyond change the import path, `/v2`, in every module
  in the repository.
- The `go` directive is a compatibility promise. Raising it is a breaking
  change for anybody on the older toolchain, so it belongs in a minor bump
  with a changelog entry.
- `retract` is the tool for a release that should never have happened. Use
  it rather than deleting a tag.

## After a release

- Check that pkg.go.dev has rendered the documentation for every module.
- Check that the Go Report Card is still clean.
- Open the next `## [Unreleased]` section in `CHANGELOG.md`.
