#!/usr/bin/env bash
#
# Build every module for every platform this library claims to support.
#
# CI runs the tests on Linux, macOS, and Windows. This is the other half:
# proof that the code compiles for the platforms nobody runs a runner on,
# so that a syscall or a build tag that only exists on one of them is
# caught here rather than on somebody's Raspberry Pi.

set -euo pipefail

cd "$(dirname "$0")/.."

PLATFORMS=(
	linux/amd64
	linux/arm64
	linux/386
	linux/arm
	darwin/amd64
	darwin/arm64
	windows/amd64
	windows/386
	windows/arm64
	freebsd/amd64
	openbsd/amd64
	netbsd/amd64
	illumos/amd64
	solaris/amd64
	js/wasm
	wasip1/wasm
)

MODULES=(. contrib/gin contrib/echo contrib/fiber)

# Platforms a module genuinely cannot support, and why. An exclusion is a
# statement about somebody else's dependency, so it says whose.
#
# Fiber is built on fasthttp, whose listener has no implementation for the
# wasm targets. The root module and the net/http-based adapters build for
# everything on the list.
EXCLUSIONS=(
	"contrib/fiber js/wasm"
	"contrib/fiber wasip1/wasm"
)

excluded() {
	local candidate="$1 $2"

	for exclusion in "${EXCLUSIONS[@]}"; do
		if [ "$exclusion" = "$candidate" ]; then
			return 0
		fi
	done

	return 1
}

failed=0

for module in "${MODULES[@]}"; do
	built=0

	for platform in "${PLATFORMS[@]}"; do
		os="${platform%/*}"
		arch="${platform#*/}"

		if excluded "$module" "$platform"; then
			continue
		fi

		built=$((built + 1))

		if ! output=$(cd "$module" && GOOS="$os" GOARCH="$arch" go build ./... 2>&1); then
			echo "FAIL $module $platform"
			echo "$output" | sed 's/^/    /'
			failed=$((failed + 1))
		fi
	done

	echo "==> $module builds for $built of ${#PLATFORMS[@]} platforms"
done

if [ "$failed" -gt 0 ]; then
	echo "$failed platform builds failed" >&2
	exit 1
fi
