#!/usr/bin/env bash
#
# Bring up the directory in integration/compose.yml, apply the ACL the
# suite needs, and run the integration tests against it.
#
#   scripts/integration.sh              # up, test, leave it running
#   scripts/integration.sh --down       # tear it down afterwards
#   scripts/integration.sh -run TestX   # anything else is passed to go test
#
# The container is left running by default so that a second run is fast and
# so that a failure can be poked at with ldapsearch.

set -euo pipefail

cd "$(dirname "$0")/.."

die() {
	echo "integration: $*" >&2
	exit 1
}

command -v docker >/dev/null || die "docker is not installed"

COMPOSE=(docker compose -f integration/compose.yml)
URL="ldap://127.0.0.1:1389"
TLS_URL="ldaps://127.0.0.1:1636"
TLS_HOST="ldap.example.org"
# Absolute, because `go test` runs the binary with the package directory
# as its working directory and a relative path would resolve somewhere
# else entirely.
CA_FILE="$PWD/integration/testdata/ca.crt"

DOWN=0
ARGS=()

for arg in "$@"; do
	case "$arg" in
	--down) DOWN=1 ;;
	*) ARGS+=("$arg") ;;
	esac
done

cleanup() {
	if [ "$DOWN" = "1" ]; then
		"${COMPOSE[@]}" down --volumes >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

# ---- certificates
#
# Generated before the container starts, because it reads them at boot.
# The image ships its own CA and that CA expired in January 2026; see
# internal/tools/testca for why the workaround is not InsecureSkipVerify.

echo "==> generating certificates"
go run ./internal/tools/testca -dir integration/testdata -host "$TLS_HOST"

# ---- bring the directory up

echo "==> starting the directory"
"${COMPOSE[@]}" up -d --wait --wait-timeout 180

# ---- apply the ACL
#
# The image's bootstrap only imports entries into the data tree; the ACL
# lives in cn=config and has to go in over the local socket as root.

echo "==> applying ACLs"
"${COMPOSE[@]}" exec -T openldap \
	ldapmodify -Y EXTERNAL -H ldapi:/// -f /config/00-acl.ldif >/dev/null

# ---- run the suite

echo "==> running the integration suite against $URL and $TLS_URL"
go test -count=1 -race ./integration/ \
	-ldap-url "$URL" \
	-ldaps-url "$TLS_URL" \
	-ldap-ca "$CA_FILE" \
	"${ARGS[@]}"
