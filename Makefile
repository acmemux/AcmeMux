GO_VERSION := go1.26.6
NODE_VERSION := v20.19.2
NPM_VERSION := 9.2.0
STATICCHECK_VERSION := v0.7.0
GOVULNCHECK_VERSION := v1.7.0
GO_PACKAGES := ./cmd/... ./internal/...
export GOCACHE := $(CURDIR)/.cache/go-build
export GOMODCACHE := $(CURDIR)/.cache/go-mod

.PHONY: bootstrap browser-install build catalog distribution format-check lint run site-build site-static-check site-verify site-visual-update test test-accessibility test-broker test-browser test-compatibility test-configuration test-distribution test-filesystem test-identity test-integrations test-inventory test-jobs test-lego-integration test-nativeconfig test-provider-cloud test-provider-cloud-smoke test-provider-core test-provider-core-smoke test-race test-redaction test-reporting test-runtime test-scheduler test-site test-systemd test-upgrade test-visual test-visual-update test-web test-workspace toolchain-check verify vuln web-build web-deps web-verify

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
	cd web && npx prettier --check ../site/scripts ../site/src

lint:
	go vet $(GO_PACKAGES)
	GOTOOLCHAIN=$(GO_VERSION) go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) $(GO_PACKAGES)

test:
	go test $(GO_PACKAGES)

test-race:
	go test -race $(GO_PACKAGES)

vuln:
	GOTOOLCHAIN=$(GO_VERSION) go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(GO_PACKAGES)
	cd web && npm audit --audit-level=low

web-build:
	cd web && npm run build

web-verify:
	cd web && npm run verify

test-browser:
	cd web && npm run test:browser

test-web:
	cd web && npm run test

test-identity:
	go test ./cmd/acmemux/... ./internal/appconfig/... ./internal/httpapi/... ./internal/identity/... ./internal/state/...

test-runtime:
	go test ./cmd/acmemux/... ./internal/httpapi/... ./internal/runtime/... ./internal/state/...

test-compatibility:
	go test ./internal/compatibility/...

test-workspace:
	go test ./internal/workspace/... ./internal/state/...

test-inventory:
	go test ./internal/inventory/...

test-broker:
	go test ./internal/broker/...

test-jobs:
	go test ./internal/jobs/... ./internal/operation/... ./internal/state/...

test-scheduler:
	go test ./internal/scheduler/... ./internal/jobs/... ./internal/operation/... ./internal/httpapi/... ./internal/state/...

test-lego-integration:
	@test -n "$$ACMEMUX_TEST_LEGO" || (echo "ACMEMUX_TEST_LEGO must name the source-built lego executable" && exit 1)
	@test -n "$$ACMEMUX_TEST_PEBBLE" || (echo "ACMEMUX_TEST_PEBBLE must name the pinned Pebble executable" && exit 1)
	@test -n "$$ACMEMUX_TEST_CHALLTESTSRV" || (echo "ACMEMUX_TEST_CHALLTESTSRV must name the pinned challtestsrv executable" && exit 1)
	@test -n "$$ACMEMUX_TEST_LEGO_SOURCE" || (echo "ACMEMUX_TEST_LEGO_SOURCE must name the upstream lego source snapshot" && exit 1)
	ACMEMUX_TEST_LEGO_INTEGRATION=1 go test -count=1 -timeout=5m -run '^TestSourceBuiltLegoFileMode$$' ./internal/broker/...
	ACMEMUX_TEST_LEGO_INTEGRATION=1 go test -count=1 -timeout=5m -run '^TestCoreDNSUpstreamProviderFixtures$$' ./internal/integrations/...
	ACMEMUX_TEST_LEGO_INTEGRATION=1 go test -count=1 -timeout=5m -run '^TestCloudDNSUpstreamProviderFixtures$$' ./internal/integrations/...

test-integrations:
	go test ./internal/integrations/...

test-provider-core:
	go test ./internal/integrations/... ./internal/nativeconfig/... ./internal/configuration/... ./internal/httpapi/...
	cd web && npm run test -- src/app/nativeConfigurationModel.test.ts src/app/NativeConfigurationFields.test.tsx

test-provider-cloud:
	go test ./internal/integrations/... ./internal/nativeconfig/... ./internal/configuration/... ./internal/workspace/... ./internal/broker/... ./internal/operation/... ./internal/httpapi/...
	cd web && npm run test -- src/api/operations.test.ts src/app/nativeConfigurationModel.test.ts src/app/NativeConfigurationFields.test.tsx src/app/OperationsPanel.test.tsx

test-provider-core-smoke:
	@test "$$ACMEMUX_PROVIDER_SMOKE" = "1" || (echo "ACMEMUX_PROVIDER_SMOKE=1 is required for credentialed provider smoke" && exit 1)
	go test -count=1 -run '^TestCredentialedDNSProviderSmoke$$' ./internal/integrations/...

test-provider-cloud-smoke: test-provider-core-smoke

test-nativeconfig:
	go test ./internal/integrations/... ./internal/nativeconfig/... ./internal/configuration/...

test-filesystem:
	go test ./internal/workspace/... ./internal/state/...

test-redaction:
	go test ./internal/dotenv/... ./internal/redaction/...

test-reporting:
	go test ./internal/reporting/... ./internal/inventory/... ./internal/jobs/... ./internal/httpapi/...
	cd web && npm run test -- src/api/workspace.test.ts src/api/operations.test.ts src/app/WorkspacePanel.test.tsx src/app/OperationsPanel.test.tsx

test-configuration: test-nativeconfig test-filesystem test-redaction
	go test ./internal/httpapi/... ./cmd/acmemux/...

test-accessibility:
	cd web && npm run test:accessibility

test-visual:
	cd web && npm run test:visual

test-visual-update:
	cd web && npm run test:visual:update

site-build: toolchain-check
	node site/scripts/build.mjs

site-static-check: site-build
	cd web && npm run site:static

test-site: site-build
	cd web && npm run test:site

site-visual-update: site-build
	cd web && npm run test:site:visual:update

site-verify: site-static-check
	@first="$$(sha256sum site/dist/BUILD.json | awk '{ print $$1 }')"; \
		$(MAKE) --no-print-directory site-build >/dev/null; \
		second="$$(sha256sum site/dist/BUILD.json | awk '{ print $$1 }')"; \
		test "$$first" = "$$second" || (echo "public site build is not reproducible" && exit 1)
	cd web && npm run test:site

catalog:
	cd web && npm run catalog

build: web-build
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/acmemux ./cmd/acmemux

distribution: toolchain-check build
	cd dist && sha256sum acmemux > acmemux.sha256

test-distribution: distribution
	shellcheck distribution/lib.sh distribution/install.sh distribution/upgrade.sh distribution/remove.sh distribution/tests/*.sh
	distribution/tests/install_test.sh
	@first="$$(sha256sum dist/acmemux | awk '{ print $$1 }')"; \
		$(MAKE) --no-print-directory build >/dev/null; \
		second="$$(sha256sum dist/acmemux | awk '{ print $$1 }')"; \
		test "$$first" = "$$second" || (echo "source build is not reproducible" && exit 1)

test-upgrade: distribution
	distribution/tests/upgrade_test.sh

test-systemd: distribution
	distribution/tests/unit_verify.sh
	distribution/tests/systemd_smoke.sh
	distribution/tests/native_install_smoke.sh

run: web-build
	@test -n "$(ACMEMUX_PUBLIC_ORIGIN)" || (echo "ACMEMUX_PUBLIC_ORIGIN must name the HTTPS browser origin" && exit 1)
	go run ./cmd/acmemux serve --state-dir ./var

verify: toolchain-check format-check lint test test-race vuln web-verify test-browser site-verify build test-distribution test-upgrade test-systemd
