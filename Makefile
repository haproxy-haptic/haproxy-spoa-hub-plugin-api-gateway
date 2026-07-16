.PHONY: test lint fmt fmt-fix build check

test:
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt -- --check

fmt-fix:
	cargo fmt

build:
	cargo build --release

check: fmt lint test build
