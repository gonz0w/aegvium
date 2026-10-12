.PHONY: tools hooks check lint test secrets verify
tools:
	python3 tools/bootstrap-tools.py
hooks:
	git config core.hooksPath .githooks
check:
	sh tools/check-repo.sh
lint:
	.tools/bin/shellcheck tools/check-repo.sh .githooks/pre-commit .githooks/commit-msg
test:
	.tools/venv/bin/python3 -m unittest discover -s tools/tests -v
secrets:
	.tools/bin/gitleaks dir --redact --no-banner --config .gitleaks.toml .
verify: check lint test secrets
