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
#
# The worker count is capped, and that is not a performance decision. Left
# alone, go test starts one fuzzing worker per core: on a 28-core machine
# that is 32 worker processes and about 3.5 GB, all competing for the cores
# the coordinator also needs. When the run ends, the coordinator asks the
# workers to stop and waits — and under that contention one of them misses
# the deadline, which surfaces as
#
#     --- FAIL: FuzzSomething (30.13s)
#         context deadline exceeded
#
# a failure with nothing at all to do with the property under test. A gate
# that fails because the machine was busy is a gate people learn to ignore.
#
# Eight, or the core count if that is smaller: enough headroom on a big
# machine that the coordinator is never starved, and no change at all on a
# two-core CI runner, which would have used two either way.

set -euo pipefail

cd "$(dirname "$0")/.."

FUZZTIME="${1:-30s}"

cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
FUZZWORKERS="${FUZZWORKERS:-$((cores < 8 ? cores : 8))}"

found=0

for package in $(go list ./... | grep -v '/examples/'); do
	dir=$(go list -f '{{.Dir}}' "$package")

	targets=$(grep -rhoE '^func (Fuzz[A-Za-z0-9_]*)\(' "$dir"/*_test.go 2>/dev/null |
		sed -E 's/^func //; s/\($//' | sort -u || true)

	for target in $targets; do
		found=$((found + 1))
		echo "==> $package $target ($FUZZTIME, $FUZZWORKERS workers)"
		go test -run '^$' -fuzz "^${target}\$" -fuzztime "$FUZZTIME" -parallel "$FUZZWORKERS" "$package"
	done
done

if [ "$found" -eq 0 ]; then
	echo "no fuzz targets found; the discovery is broken" >&2
	exit 1
fi

echo "==> ran $found fuzz targets"
