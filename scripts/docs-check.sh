#!/usr/bin/env bash
#
# Check that the documentation and the repository still agree.
#
# Documentation rots quietly: a doc file that nothing links to stops being
# read, a link to a file that was renamed stops working, and an example
# directory nobody mentions stops being run. None of that breaks a build,
# which is exactly why it needs a check of its own.
#
# What this asserts:
#
#   - every docs/*.md is linked from README.md
#   - every relative link in a markdown file points at something that exists
#   - every examples/* directory is listed in README.md
#   - every module has a README

set -euo pipefail

cd "$(dirname "$0")/.."

findings=$(mktemp)
trap 'rm -f "$findings"' EXIT

fail() {
	echo "docs-check: $*" >>"$findings"
}

# ---- every doc is reachable from the README

for doc in docs/*.md; do
	if ! grep -qF "$doc" README.md; then
		fail "$doc is not linked from README.md"
	fi
done

# ---- every relative link points at something
#
# The greps are guarded with || true: a file with no links at all is not a
# failure, and under pipefail an empty grep would otherwise end the script.

for source in $(find . -name '*.md' -not -path './.git/*' | sort); do
	targets=$(grep -oE '\]\([^)]+\)' "$source" 2>/dev/null || true)

	for target in $(echo "$targets" | sed -E 's/^\]\(//; s/\)$//; s/#.*$//' | grep -vE '^(https?:|mailto:|#|$)' || true); do
		resolved="$(dirname "$source")/$target"

		if [ ! -e "$resolved" ]; then
			fail "$source links to $target, which does not exist"
		fi
	done
done

# ---- every example is mentioned

for example in examples/*/; do
	name="${example%/}"

	if ! grep -qF "$name" README.md; then
		fail "$name is not listed in README.md"
	fi
done

# ---- every module documents itself

for module in . contrib/gin contrib/echo contrib/fiber; do
	if [ ! -f "$module/README.md" ]; then
		fail "$module has no README.md"
	fi
done

if [ -s "$findings" ]; then
	cat "$findings" >&2
	echo >&2
	echo "$(wc -l <"$findings" | tr -d ' ') documentation problems" >&2
	exit 1
fi

echo "documentation and repository agree"
