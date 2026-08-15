GO_VERSION := go1.26.6
NODE_VERSION := v20.19.2
NPM_VERSION := 9.2.0
STATICCHECK_VERSION := v0.7.0
GOVULNCHECK_VERSION := v1.7.0
GO_PACKAGES := ./cmd/... ./internal/...
export GOCACHE := $(CURDIR)/.cache/go-build

.PHONY: bootstrap browser-install build format-check lint run test test-browser test-race toolchain-check verify vuln web-build web-deps web-verify

bootstrap: toolchain-check web-deps browser-install

web-deps:
	cd web && npm ci

browser-install:
	cd web && npx playwright install --with-deps chromium

toolchain-check:
	@test "$$(go version | awk '{print $$3}')" = "$(GO_VERSION)" || (echo "Go $(GO_VERSION) is required" && exit 1)
	@test "$$(node --version)" = "$(NODE_VERSION)" || (echo "Node.js $(NODE_VERSION) is required" && exit 1)
	@test "$$(npm --version)" = "$(NPM_VERSION)" || (echo "npm $(NPM_VERSION) is required" && exit 1)

format-check:
	@test -z "$$(gofmt -l $$(find cmd internal -name '*.go' -type f))" || (gofmt -l $$(find cmd internal -name '*.go' -type f) && exit 1)
	cd web && npm run format:check

lint:
	go vet $(GO_PACKAGES)
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) $(GO_PACKAGES)

test:
	go test $(GO_PACKAGES)

test-race:
	go test -race $(GO_PACKAGES)

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(GO_PACKAGES)
	cd web && npm audit --audit-level=high

web-build:
	cd web && npm run build

web-verify:
	cd web && npm run verify

test-browser:
	cd web && npm run test:browser

build: web-build
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/acmemux ./cmd/acmemux

run: web-build
	go run ./cmd/acmemux serve --state-dir ./var

verify: toolchain-check format-check lint test test-race vuln web-verify test-browser build
