#!/usr/bin/env bash
#
# Configure the GitHub repository the way this project's workflows expect.
#
#   scripts/github-setup.sh              # show what would change
#   scripts/github-setup.sh --apply      # change it
#
# Everything here is a repository setting rather than a file, which is
# exactly why it is a script: settings that live only in somebody's memory
# of a settings page are settings that quietly stop being true.
#
# Requires the GitHub CLI, authenticated with admin rights on the repo.

set -euo pipefail

cd "$(dirname "$0")/.."

readonly REPO=ctolon/ldap-authenticator
readonly BRANCH=main

# The one required check. ci-green aggregates the rest, so adding a job to
# the workflow does not mean editing the branch rules.
readonly REQUIRED_CHECK=ci-green

APPLY=0
if [ "${1:-}" = "--apply" ]; then
	APPLY=1
fi

die() {
	echo "github-setup: $*" >&2
	exit 1
}

command -v gh >/dev/null || die "the GitHub CLI is not installed"

gh auth status >/dev/null 2>&1 || die "gh is not authenticated"

run() {
	if [ "$APPLY" = "1" ]; then
		echo "==> $*"
		"$@"
	else
		echo "would run: $*"
	fi
}

echo "repository: $REPO"
echo

# ---- security features
#
# Private vulnerability reporting is what SECURITY.md points people at. A
# security policy with nowhere to report to is a security policy that
# produces public issues describing vulnerabilities.

echo "-- security --"
run gh api -X PATCH "repos/$REPO" \
	-f 'security_and_analysis[secret_scanning][status]=enabled' \
	-f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'

run gh api -X PUT "repos/$REPO/private-vulnerability-reporting"

# Dependabot alerts. The workflow raises the pins; this is what tells it to.
run gh api -X PUT "repos/$REPO/vulnerability-alerts"

echo

# ---- branch protection
#
# The rules that make the gate mean something: main is not directly
# pushable, and a pull request has to be green and reviewed.

echo "-- branch protection on $BRANCH --"
protection=$(mktemp)
trap 'rm -f "$protection"' EXIT

cat >"$protection" <<JSON
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["$REQUIRED_CHECK"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON

if [ "$APPLY" = "1" ]; then
	echo "==> applying branch protection"
	gh api -X PUT "repos/$REPO/branches/$BRANCH/protection" --input "$protection"
else
	echo "would apply:"
	sed 's/^/    /' "$protection"
fi

echo

# ---- workflow permissions
#
# The default token is read-only; the release workflow asks for the write
# it needs, at the job that needs it.

echo "-- actions --"
run gh api -X PUT "repos/$REPO/actions/permissions/workflow" \
	-f default_workflow_permissions=read \
	-F can_approve_pull_request_reviews=false

echo

# ---- repository metadata

echo "-- metadata --"
run gh repo edit "$REPO" \
	--description "Production LDAP authentication for Go, with one dependency" \
	--homepage "https://pkg.go.dev/github.com/ctolon/ldap-authenticator" \
	--add-topic ldap \
	--add-topic authentication \
	--add-topic golang \
	--add-topic active-directory \
	--add-topic openldap \
	--add-topic middleware \
	--enable-issues \
	--enable-discussions \
	--enable-wiki=false \
	--enable-projects=false

echo

if [ "$APPLY" != "1" ]; then
	echo "nothing was changed. re-run with --apply."
fi
