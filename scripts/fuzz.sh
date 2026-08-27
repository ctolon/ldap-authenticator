#!/usr/bin/env bash
#
# Run every fuzz target in the repository for the given duration.
#
#   scripts/fuzz.sh 30s
#
# The list is discovered rather than written down, so a target added
# without being wired up here still runs — a fuzz target nobody runs is a
# fuzz target that is not testing anything.
#
# Patterns are anchored because target names overlap: -fuzz FuzzCredentials
# would match FuzzCredentialsRefusesAnEmptyRequest too, and go test refuses
# to fuzz when the pattern matches more than one.

set -euo pipefail

cd "$(dirname "$0")/.."

FUZZTIME="${1:-30s}"

found=0

for package in $(go list ./... | grep -v '/examples/'); do
	dir=$(go list -f '{{.Dir}}' "$package")

	targets=$(grep -rhoE '^func (Fuzz[A-Za-z0-9_]*)\(' "$dir"/*_test.go 2>/dev/null |
		sed -E 's/^func //; s/\($//' | sort -u || true)

	for target in $targets; do
		found=$((found + 1))
		echo "==> $package $target ($FUZZTIME)"
		go test -run '^$' -fuzz "^${target}\$" -fuzztime "$FUZZTIME" "$package"
	done
done

if [ "$found" -eq 0 ]; then
	echo "no fuzz targets found; the discovery is broken" >&2
	exit 1
fi

echo "==> ran $found fuzz targets"
