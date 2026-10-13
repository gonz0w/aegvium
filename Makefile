.PHONY: tools hooks check lint test secrets verify
tools:
	python3 tools/bootstrap-tools.py
hooks:
	git config core.hooksPath .githooks
check:
	sh tools/check-repo.sh
lint:
	.tools/bin/shellcheck tools/native/relayd-traffic.sh tools/native/relayd-checker-contract.sh tools/native/relayd-signals.sh tools/native/relayd-wiring.sh tools/native/relayd-health-faults.sh tools/native/relayd-checker-replacement.sh tools/native/relayd-generations.sh research/relayd/checker-exit2.sh tools/native/relayd-config.sh tools/native/source-build.sh tools/native/engine-repeat.sh tools/native/patch-openbsd.sh tools/run-research-go.sh tools/check-repo.sh .githooks/pre-commit .githooks/commit-msg
test:
	.tools/venv/bin/python3 -m unittest discover -s tools/tests -v
secrets:
	.tools/bin/gitleaks dir --redact --no-banner --config .gitleaks.toml .
verify: check lint test secrets

.PHONY: research-test research-cross
research-test:
	cd research/coraza && ../../tools/run-research-go.sh test -count=1 -v ./...
research-cross:
	mkdir -p .tools/research
	cd research/coraza && GOOS=openbsd GOARCH=amd64 CGO_ENABLED=0 ../../tools/run-research-go.sh test -c -o ../../.tools/research/coraza-openbsd-amd64.test

.PHONY: research-tools research-audit
research-tools:
	python3 tools/bootstrap-research.py

research-audit:
	cd research/coraza && PATH=$(CURDIR)/.tools/go/bin:$$PATH GOTOOLCHAIN=local ../../.tools/research-bin/govulncheck -test ./...

.PHONY: research-native
research-native:
	python3 tools/native-engine.py

.PHONY: research-native-build
research-native-build:
	python3 tools/native-engine.py --source-build

.PHONY: research-relayd-config
research-relayd-config:
	python3 tools/native-engine.py --relayd-config

.PHONY: research-relayd-traffic
research-relayd-traffic:
	python3 tools/native-engine.py --relayd-traffic

.PHONY: research-readycheck-cross
research-readycheck-cross:
	mkdir -p .tools/research
	cd research/coraza && GOOS=openbsd GOARCH=amd64 CGO_ENABLED=0 ../../tools/run-research-go.sh build -o ../../.tools/research/readycheck-openbsd-amd64 ./cmd/readycheck

.PHONY: research-signalobserve-cross
research-signalobserve-cross:
	mkdir -p .tools/research
	cd research/coraza && GOOS=openbsd GOARCH=amd64 CGO_ENABLED=0 ../../tools/run-research-go.sh build -o ../../.tools/research/signalobserve-openbsd-amd64 ./cmd/signalobserve

.PHONY: research-relayd-contract
research-relayd-contract:
	python3 tools/native-engine.py --relayd-contract

.PHONY: research-relayd-signals
research-relayd-signals:
	python3 tools/native-engine.py --relayd-signals

.PHONY: research-relayd-wiring
research-relayd-wiring:
	python3 tools/native-engine.py --relayd-wiring

.PHONY: research-relayd-health-faults
research-relayd-health-faults:
	python3 tools/native-engine.py --relayd-health-faults

.PHONY: research-relayd-checker-replacements
research-relayd-checker-replacements:
	python3 tools/native-engine.py --relayd-checker-replacements

.PHONY: research-relayd-generations
research-relayd-generations:
	python3 tools/native-engine.py --relayd-generations

.PHONY: research-native-generations
research-native-generations:
	python3 tools/native-engine.py --source-build --relayd-generations
