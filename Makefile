.PHONY: tools hooks check lint test secrets verify
tools:
	python3 tools/bootstrap-tools.py
hooks:
	git config core.hooksPath .githooks
check:
	sh tools/check-repo.sh
lint:
	.tools/bin/shellcheck tools/native/source-build.sh tools/native/engine-repeat.sh tools/native/patch-openbsd.sh tools/run-research-go.sh tools/check-repo.sh .githooks/pre-commit .githooks/commit-msg
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
