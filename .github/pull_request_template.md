## What this changes

<!-- And why. The what is in the diff; the why is not. -->

## Checklist

- [ ] `make check` passes
- [ ] `make integration` passes, if this touches anything the directory sees
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]`, if behaviour changed
- [ ] `api_test.go` is updated, if an exported signature changed
- [ ] New behaviour has a test; the test's name says what it protects

## Security invariants

<!-- Delete this section if it does not apply. -->

This change touches one of the invariants in `SECURITY.md`. Which one, and
why the change is safe:
