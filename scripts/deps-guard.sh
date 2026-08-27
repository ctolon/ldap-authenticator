#!/usr/bin/env bash
#
# Assert that the root module has exactly one direct dependency.
#
# The single dependency is this library's headline claim, and a claim that
# is only enforced by good intentions is a claim that lasts until the first
# convenient import. So it is a build failure instead.
#
# The contrib modules are exempt: each one exists precisely to hold a
# framework dependency that the root module refuses to take on.

set -euo pipefail

cd "$(dirname "$0")/.."

readonly EXPECTED="github.com/go-ldap/ldap/v3"

direct=$(go list -m -f '{{if not .Indirect}}{{if not .Main}}{{.Path}}{{end}}{{end}}' all | grep -v '^$' || true)

if [ "$direct" != "$EXPECTED" ]; then
	echo "the root module's direct dependencies changed." >&2
	echo >&2
	echo "  want: $EXPECTED" >&2
	echo "  got:  ${direct:-<none>}" >&2
	echo >&2
	echo "A new dependency in the root module breaks the promise on the front" >&2
	echo "of the README. If the code needs a framework, it belongs in a" >&2
	echo "contrib module; if it needs a library, it probably belongs in the" >&2
	echo "standard library instead." >&2
	exit 1
fi

echo "root module direct dependencies: $direct"
