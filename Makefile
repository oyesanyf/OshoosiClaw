# Makefile for OpenỌ̀ṣọ́ọ̀sì (OshoosiClaw)
# Supports Unix Make and Windows GNU Make / WSL

.PHONY: all check test webui-test verify-onboarding docker-test lint clean help

all: check test verify-onboarding

help:
	@echo "OshoosiClaw Build & Verification Targets:"
	@echo "  make check              - Fast compilation check of all workspace targets"
	@echo "  make test               - Run all Rust tests across the workspace"
	@echo "  make webui-test         - Verify WebUI 0-diff parity between src/ and dist/"
	@echo "  make verify-onboarding  - Run repo clarity, language distribution & README link validation"
	@echo "  make docker-test        - Build the hardened non-root container image"
	@echo "  make lint               - Run cargo clippy and cargo fmt checks"
	@echo "  make clean              - Remove build artifacts and target/ directory"

check:
	cargo check --all-targets

test:
	cargo test --all-features

webui-test:
	node dashboard/tests/webui_parity.test.mjs

verify-onboarding:
	python scripts/verify_repo_clarity_and_languages.py
	python scripts/validate_readme.py

docker-test:
	docker build -t ghcr.io/oyesanyf/oshoosiclaw:test .

lint:
	cargo clippy --all-features -- -D warnings
	cargo fmt --all -- --check

clean:
	cargo clean
