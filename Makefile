# Everything CI runs, runnable locally. `make check` is the gate.

GO ?= go
FUZZTIME ?= 30s
BENCHTIME ?= 200ms

# The contrib modules are separate so that the root module can keep its
# single dependency. That means every target that walks the tree has to
# walk them too, and it is why so many of these loop.
CONTRIB := contrib/gin contrib/echo contrib/fiber

# Analysis tools are pinned, and CI uses these same variables. An @latest
# here would mean a new upstream release can turn main red without a single
# change to this repository — a build that is not reproducible is a build
# that cannot tell you whether your own change broke something.
#
# Dependabot does not see these, so they are reviewed and raised by hand
# when there is a reason to.
STATICCHECK_VERSION ?= v0.8.1
GOVULNCHECK_VERSION ?= v1.7.0

.PHONY: all
all: check

## check: the full gate — format, vet, lint, race tests, fuzz smoke, dependencies, vulnerabilities
.PHONY: check
check: fmt-check vet staticcheck test-race contrib deps-guard fuzz-smoke vuln

## test: run every test in the root module
.PHONY: test
test:
	$(GO) test ./...

## test-race: run every test under the race detector
.PHONY: test-race
test-race:
	$(GO) test -race -count=1 ./...

## contrib: build, vet, and test each contrib module
.PHONY: contrib
contrib:
	@for module in $(CONTRIB); do \
		echo "==> $$module"; \
		( cd $$module && $(GO) build ./... && $(GO) vet ./... && $(GO) test -race -count=1 ./... ) || exit 1; \
	done

## deps-guard: assert the root module still has exactly one direct dependency
.PHONY: deps-guard
deps-guard:
	@./scripts/deps-guard.sh

## integration: bring up a real directory and run the integration suite
.PHONY: integration
integration:
	./scripts/integration.sh

## integration-down: tear the integration directory down
.PHONY: integration-down
integration-down:
	docker compose -f integration/compose.yml down --volumes

## bench: run the benchmarks
.PHONY: bench
bench:
	$(GO) test -run '^$$' -bench . -benchmem -benchtime $(BENCHTIME) ./benchmarks/

## bench-compile: make sure the benchmarks still build, without running them
.PHONY: bench-compile
bench-compile:
	$(GO) test -run '^$$' -bench . -benchtime 1x ./benchmarks/

## fuzz-smoke: run each fuzz target briefly, as CI does on every push
.PHONY: fuzz-smoke
fuzz-smoke:
	$(GO) test -run '^$$' -fuzz FuzzEscapeFilterValue -fuzztime $(FUZZTIME) .
	$(GO) test -run '^$$' -fuzz FuzzEscapeDNValue -fuzztime $(FUZZTIME) .
	$(GO) test -run '^$$' -fuzz FuzzParseTemplate -fuzztime $(FUZZTIME) .
	$(GO) test -run '^$$' -fuzz FuzzCheckUsername -fuzztime $(FUZZTIME) .

## fmt: format the tree
.PHONY: fmt
fmt:
	gofmt -w -s .

## fmt-check: fail if anything is unformatted
.PHONY: fmt-check
fmt-check:
	@unformatted=$$(gofmt -l -s .); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-ed:"; echo "$$unformatted"; exit 1; \
	fi

## vet: run go vet across every module
.PHONY: vet
vet:
	$(GO) vet ./...
	@for module in $(CONTRIB); do ( cd $$module && $(GO) vet ./... ) || exit 1; done

## staticcheck: run staticcheck across every module
.PHONY: staticcheck
staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...
	@for module in $(CONTRIB); do \
		( cd $$module && $(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./... ) || exit 1; \
	done

## vuln: scan dependencies for known vulnerabilities
.PHONY: vuln
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	@for module in $(CONTRIB); do \
		( cd $$module && $(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./... ) || exit 1; \
	done

## tidy: tidy every module
.PHONY: tidy
tidy:
	$(GO) mod tidy
	@for module in $(CONTRIB); do ( cd $$module && $(GO) mod tidy ) || exit 1; done

## examples: build every example, in every module
.PHONY: examples
examples:
	$(GO) build -o /dev/null ./examples/...
	@for module in $(CONTRIB); do ( cd $$module && $(GO) build -o /dev/null ./... ) || exit 1; done

## help: list the targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
