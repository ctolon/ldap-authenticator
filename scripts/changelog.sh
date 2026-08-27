#!/usr/bin/env bash
#
# Print the changelog section for one version.
#
#   scripts/changelog.sh 0.1.0
#
# The release workflow uses it to build release notes, and to fail a
# release that has none: a release nobody wrote notes for is a release
# nobody can decide whether to take.

set -euo pipefail

cd "$(dirname "$0")/.."

die() {
	echo "changelog: $*" >&2
	exit 1
}

[ $# -eq 1 ] || die "usage: changelog.sh X.Y.Z"

version="${1#v}"

[ -f CHANGELOG.md ] || die "no CHANGELOG.md"

# Print everything between this version's heading and the next one,
# stopping before the link-reference block at the foot of the file.
section=$(awk -v version="$version" '
	$0 ~ "^## \\[" version "\\]" { inside = 1; next }
	inside && /^## / { exit }
	inside { print }
' CHANGELOG.md)

# Trim the blank lines the extraction leaves at either end.
section=$(printf '%s\n' "$section" | sed -e '/./,$!d' -e :a -e '/^\n*$/{$d;N;ba' -e '}')

[ -n "$section" ] || die "CHANGELOG.md has no section for $version"

printf '%s\n' "$section"
