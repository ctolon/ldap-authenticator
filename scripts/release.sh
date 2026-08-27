#!/usr/bin/env bash
#
# Cut a release. The tag is the release; this creates it locally and
# pushes nothing.
#
#   scripts/release.sh patch            # 0.1.0 -> 0.1.1
#   scripts/release.sh minor            # 0.1.0 -> 0.2.0
#   scripts/release.sh major            # 0.1.0 -> 1.0.0
#   scripts/release.sh 0.4.0            # an explicit version
#   scripts/release.sh --contrib 0.4.0  # the contrib tags, after the root
#                                       # tag has been pushed and indexed
#
# Pushing is deliberately a separate act. See RELEASING.md, and note that
# the root tag has to be visible to the module proxy before the contrib
# tags are pushed.

set -euo pipefail

cd "$(dirname "$0")/.."

readonly BRANCH=main
readonly CONTRIB=(contrib/gin contrib/echo contrib/fiber)

die() {
	echo "release: $*" >&2
	exit 1
}

# required_root_version prints the version of the root module that a
# contrib module's go.mod requires, or nothing when it requires none.
required_root_version() {
	(
		cd "$1" && go mod edit -json | python3 -c '
import json
import sys

requires = json.load(sys.stdin).get("Require") or []
print(next((r["Version"] for r in requires if r["Path"] == "github.com/ctolon/ldap-authenticator"), ""))
'
	)
}

# ---- contrib mode
#
# The contrib modules carry no changelog and no version of their own; they
# are tagged with the root version they were released alongside, which is
# also the version their go.mod requires.

if [ "${1:-}" = "--contrib" ]; then
	version="${2:-}"
	[ -n "$version" ] || die "usage: release.sh --contrib X.Y.Z"
	version="${version#v}"

	if ! git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
		die "v$version is not tagged; release the root module first"
	fi

	# The commit the root tag names, not HEAD. Between cutting the root
	# release and pushing the contrib tags there is a wait for the module
	# proxy, and a repository does not stop moving during it — contrib
	# modules tagged at HEAD would be built from code the root release
	# never contained.
	root_commit=$(git rev-list -n1 "v$version")

	for module in "${CONTRIB[@]}"; do
		required=$(required_root_version "$module")

		if [ "$required" != "v$version" ]; then
			die "$module/go.mod requires ${required:-nothing}, not v$version"
		fi

		tag="$module/v$version"

		if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
			die "$tag already exists"
		fi

		git tag -a "$tag" -m "$module v$version" "$root_commit"
		echo "tagged $tag at ${root_commit:0:12}"
	done

	echo
	echo "push them once v$version is indexed by the proxy:"
	echo "  git push origin ${CONTRIB[*]/%//v$version}"
	exit 0
fi

# ---- root module

bump="${1:-}"
[ -n "$bump" ] || die "usage: release.sh patch|minor|major|X.Y.Z"

# ---- preconditions

[ -z "$(git status --porcelain)" ] || die "the working tree is dirty"

current_branch=$(git rev-parse --abbrev-ref HEAD)
[ "$current_branch" = "$BRANCH" ] || die "on $current_branch, expected $BRANCH"

previous=$(git tag --list 'v*' --sort=-v:refname | head -n1)
previous="${previous#v}"
previous="${previous:-0.0.0}"

case "$bump" in
patch | minor | major)
	IFS=. read -r major minor patch <<<"$previous"

	case "$bump" in
	major) major=$((major + 1)); minor=0; patch=0 ;;
	minor) minor=$((minor + 1)); patch=0 ;;
	patch) patch=$((patch + 1)) ;;
	esac

	version="$major.$minor.$patch"
	;;
*)
	version="${bump#v}"

	[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
		|| die "$bump is not a semantic version"
	;;
esac

if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
	die "v$version already exists"
fi

unreleased=$(awk '/^## \[Unreleased\]/ { inside = 1; next } inside && /^## / { exit } inside { print }' CHANGELOG.md | tr -d '[:space:]')
[ -n "$unreleased" ] || die "the Unreleased section of CHANGELOG.md is empty"

# ---- the gate

echo "==> $previous -> $version"
echo "==> running the gate"
make check

# ---- rotate the changelog

echo "==> rotating the changelog"

today=$(date -u +%Y-%m-%d)

python3 - "$version" "$today" <<'PY'
import re
import sys

version, today = sys.argv[1], sys.argv[2]
path = "CHANGELOG.md"

text = open(path).read()

if f"## [{version}]" in text:
	sys.exit(f"CHANGELOG.md already has a section for {version}")

text = text.replace(
	"## [Unreleased]\n",
	f"## [Unreleased]\n\n## [{version}] - {today}\n",
	1,
)

repo = "https://github.com/ctolon/ldap-authenticator"

text = re.sub(
	r"^\[Unreleased\]: .*$",
	f"[Unreleased]: {repo}/compare/v{version}...HEAD",
	text,
	count=1,
	flags=re.M,
)

previous = re.search(r"^\[(\d+\.\d+\.\d+[^\]]*)\]: ", text, flags=re.M)
link = (
	f"[{version}]: {repo}/compare/v{previous.group(1)}...v{version}"
	if previous
	else f"[{version}]: {repo}/releases/tag/v{version}"
)

text = re.sub(r"^(\[Unreleased\]: .*)$", r"\1\n" + link, text, count=1, flags=re.M)

open(path, "w").write(text)
PY

if ! ./scripts/changelog.sh "$version" >/dev/null; then
	die "the rotated changelog has no section for $version"
fi

# ---- commit and tag

git add CHANGELOG.md
git commit -m "release: v$version"
git tag -a "v$version" -m "v$version"

echo
echo "tagged v$version. nothing has been pushed."
echo
echo "  git push origin $BRANCH"
echo "  git push origin v$version"
echo
echo "then, once the proxy has indexed it:"
echo "  ./scripts/release.sh --contrib $version"
