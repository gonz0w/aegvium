.PHONY: tools hooks check lint test secrets verify
tools: storage-preflight
	python3 tools/bootstrap-tools.py
hooks:
	git config core.hooksPath .githooks
check: storage-git-check
	sh tools/check-repo.sh
lint:
	.tools/bin/shellcheck tools/run-contract-go.sh tools/native/lifecycle-components.sh tools/native/lifecycle-build.sh
	.tools/bin/shellcheck tools/native/request-wire.sh tools/native/backend-isolation.sh tools/native/sender-containment.sh tools/native/lab-tls.sh tools/native/configured-caddy.sh tools/native/connector-build.sh tools/native/connector-comparison.sh tools/native/lab-proxy.sh tools/native/relayd-body.sh tools/native/relayd-traffic.sh tools/native/relayd-checker-contract.sh tools/native/relayd-signals.sh tools/native/relayd-wiring.sh tools/native/relayd-health-faults.sh tools/native/relayd-checker-replacement.sh tools/native/relayd-generations.sh research/relayd/checker-exit2.sh tools/native/relayd-config.sh tools/native/source-build.sh tools/native/engine-repeat.sh tools/native/patch-openbsd.sh tools/run-research-go.sh tools/check-repo.sh .githooks/pre-commit .githooks/commit-msg
test:
	.tools/venv/bin/python3 -m unittest discover -s tools/tests -v
	$(MAKE) contract-check
secrets:
	.tools/bin/gitleaks dir --redact --no-banner --config .gitleaks.toml .
verify: check lint test secrets

.PHONY: contract-check contract-race contract-fuzz
contract-check: storage-preflight
	@test -z "$$(.tools/go/bin/gofmt -l internal/requestctx)"
	sh tools/run-contract-go.sh vet ./...
	sh tools/run-contract-go.sh test -count=1 -timeout=60s ./...
contract-race: storage-preflight
	sh tools/run-contract-go.sh test -race -count=1 -timeout=60s ./...
contract-fuzz: storage-preflight
	sh tools/run-contract-go.sh test ./internal/requestctx -run '^$$' -fuzz '^FuzzParsedContext$$' -fuzztime=10s -parallel=2 -timeout=30s

.PHONY: research-test research-cross
research-test: storage-preflight
	cd research/coraza && ../../tools/run-research-go.sh test -count=1 -v ./...
research-cross: storage-preflight
	mkdir -p .tools/research
	cd research/coraza && GOOS=openbsd GOARCH=amd64 CGO_ENABLED=0 ../../tools/run-research-go.sh test -c -o ../../.tools/research/coraza-openbsd-amd64.test

.PHONY: research-tools research-audit
research-tools: storage-preflight
	python3 tools/bootstrap-research.py

research-audit: storage-preflight
	cd research/coraza && PATH=$(CURDIR)/.tools/go/bin:$$PATH GOTOOLCHAIN=local ../../.tools/research-bin/govulncheck -test ./...

.PHONY: research-advisories
research-advisories: storage-preflight
	python3 tools/research-advisories.py

.PHONY: research-native
research-native: storage-image-preflight
	python3 tools/native-engine.py

.PHONY: research-lifecycle-cross research-native-lifecycle
research-lifecycle-cross: storage-preflight
	mkdir -p .tools/research
	cd research/coraza && GOOS=openbsd GOARCH=amd64 CGO_ENABLED=0 ../../tools/run-research-go.sh test -c -o ../../.tools/research/labcontrol-openbsd-amd64.test ./cmd/labproxy
research-native-lifecycle: storage-image-preflight
	python3 tools/native-engine.py --lifecycle-components

.PHONY: research-native-lifecycle-build
research-native-lifecycle-build: storage-image-preflight
	python3 tools/native-engine.py --lifecycle-source-build

.PHONY: research-native-build
research-native-build: storage-image-preflight
	python3 tools/native-engine.py --source-build

.PHONY: research-relayd-config
research-relayd-config: storage-image-preflight
	python3 tools/native-engine.py --relayd-config

.PHONY: research-relayd-traffic
research-relayd-traffic: storage-image-preflight
	python3 tools/native-engine.py --relayd-traffic

.PHONY: research-readycheck-cross
research-readycheck-cross: storage-preflight
	mkdir -p .tools/research
	cd research/coraza && GOOS=openbsd GOARCH=amd64 CGO_ENABLED=0 ../../tools/run-research-go.sh build -o ../../.tools/research/readycheck-openbsd-amd64 ./cmd/readycheck

.PHONY: research-signalobserve-cross
research-signalobserve-cross: storage-preflight
	mkdir -p .tools/research
	cd research/coraza && GOOS=openbsd GOARCH=amd64 CGO_ENABLED=0 ../../tools/run-research-go.sh build -o ../../.tools/research/signalobserve-openbsd-amd64 ./cmd/signalobserve

.PHONY: research-relayd-contract
research-relayd-contract: storage-image-preflight
	python3 tools/native-engine.py --relayd-contract

.PHONY: research-relayd-signals
research-relayd-signals: storage-image-preflight
	python3 tools/native-engine.py --relayd-signals

.PHONY: research-relayd-wiring
research-relayd-wiring: storage-image-preflight
	python3 tools/native-engine.py --relayd-wiring

.PHONY: research-relayd-health-faults
research-relayd-health-faults: storage-image-preflight
	python3 tools/native-engine.py --relayd-health-faults

.PHONY: research-relayd-checker-replacements
research-relayd-checker-replacements: storage-image-preflight
	python3 tools/native-engine.py --relayd-checker-replacements

.PHONY: research-relayd-generations
research-relayd-generations: storage-image-preflight
	python3 tools/native-engine.py --relayd-generations

.PHONY: research-native-generations
research-native-generations: storage-image-preflight
	python3 tools/native-engine.py --source-build --relayd-generations

.PHONY: research-labproxy-cross research-lab-proxy
research-labproxy-cross: storage-preflight
	mkdir -p .tools/research
	cd research/coraza && GOOS=openbsd GOARCH=amd64 CGO_ENABLED=0 ../../tools/run-research-go.sh build -o ../../.tools/research/labproxy-openbsd-amd64 ./cmd/labproxy
research-lab-proxy: storage-image-preflight
	python3 tools/native-engine.py --lab-proxy

.PHONY: research-native-lab
research-native-lab: storage-image-preflight
	python3 tools/native-engine.py --source-build --lab-proxy

.PHONY: research-connector-test research-connector-cross research-native-connector
research-connector-test: storage-preflight
	cd research/connector && AEGVIUM_CADDY_LOG_DIR=$(CURDIR)/.tools/configured-caddy/logs ../../tools/run-research-go.sh test -mod=readonly -count=1 -v ./...
research-connector-cross: storage-preflight
	python3 tools/connector-comparison.py
	cd research/connector && GOOS=openbsd GOARCH=amd64 CGO_ENABLED=0 ../../tools/run-research-go.sh test -mod=readonly -p=2 -c -o ../../.tools/research/connector-openbsd-amd64.test
research-native-connector: storage-image-preflight
	python3 tools/native-engine.py --connector-comparison

.PHONY: research-native-connector-build
research-native-connector-build: storage-image-preflight
	python3 tools/native-engine.py --connector-comparison --connector-source-build

.PHONY: research-configured-caddy
research-configured-caddy: storage-image-preflight
	python3 tools/native-engine.py --lab-proxy --connector-comparison --connector-source-build --configured-caddy

.PHONY: research-native-tls
research-native-tls: storage-image-preflight
	python3 tools/native-engine.py --source-build --lab-proxy --lab-tls

.PHONY: research-native-sender
research-native-sender: storage-image-preflight
	python3 tools/native-engine.py --source-build --lab-proxy --lab-tls --sender-containment

.PHONY: research-native-identity
research-native-identity: storage-image-preflight
	python3 tools/native-engine.py --source-build --lab-proxy --lab-tls --sender-containment --client-identity

.PHONY: research-native-backends
research-native-backends: storage-image-preflight
	python3 tools/native-engine.py --source-build --lab-proxy --lab-tls --sender-containment --client-identity --backend-isolation

.PHONY: research-native-request-wire
research-native-request-wire: storage-image-preflight
	python3 tools/native-engine.py --source-build --lab-proxy --lab-tls --sender-containment --client-identity --backend-isolation --request-wire

# Explicit authenticated stock baseline; ordinary components only.
.PHONY: research-native-official-lifecycle
research-native-official-lifecycle: storage-image-preflight
	python3 tools/native-engine.py --lifecycle-components --official-baseline

.PHONY: storage-preflight storage-image-preflight storage-git-check
storage-preflight:
	python3 tools/storage_preflight.py
storage-image-preflight:
	@test -n "$(IMAGE_OUTPUT_BUDGET_BYTES)" -a -n "$(IMAGE_PEAK_BYTES)" || { echo "Reviewed image budget and peak required" >&2; exit 1; }
	python3 tools/storage_preflight.py --image --image-budget-bytes "$(IMAGE_OUTPUT_BUDGET_BYTES)" --image-peak-bytes "$(IMAGE_PEAK_BYTES)"
storage-git-check:
	python3 tools/storage_guard.py staged --repo .
	python3 tools/storage_guard.py tree --repo .
