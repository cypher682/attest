SHELL := /usr/bin/env bash

.PHONY: demo test fmt clippy build down logs

demo:
	docker compose up --build

test:
	cargo test --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

build:
	cargo build --workspace

down:
	docker compose down -v

logs:
	docker compose logs -f
