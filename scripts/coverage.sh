#!/usr/bin/env bash
#
# Run the tests with coverage and fail below the floor.
#
#   scripts/coverage.sh 80.0
#
# The floor is a ratchet rather than a target. A drop means a change
# removed a test or added code nothing exercises, and either is worth
# noticing at the time rather than a year later.
#
# The examples and the build-time tools are excluded; see below.

set -euo pipefail

cd "$(dirname "$0")/.."

MINIMUM="${1:-80.0}"

# The examples are commands and the tools are build-time helpers; counting
# either would measure how much main() this repository has rather than how
# much of the library is tested.
covered=$(go list ./... | grep -vE '/examples/|/internal/tools/')

packages=$(echo "$covered" | paste -sd,)

# shellcheck disable=SC2086
go test -covermode=atomic -coverprofile=coverage.out -coverpkg="$packages" $covered

total=$(go tool cover -func=coverage.out | awk '/^total:/ { gsub("%", "", $3); print $3 }')

echo
go tool cover -func=coverage.out | grep -vE '\s100.0%$' | tail -n 20
echo
echo "total coverage: ${total}% (floor ${MINIMUM}%)"

if awk -v total="$total" -v minimum="$MINIMUM" 'BEGIN { exit !(total < minimum) }'; then
	echo "coverage ${total}% is below the ${MINIMUM}% floor" >&2
	exit 1
fi
