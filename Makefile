.DEFAULT_GOAL := help

COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
VERSION := snapshot-$(shell echo ${COMMIT} | cut -c1-8)
TARGET_BIN ?= bin/datadog-saist
CONSTANTS_PATH = github.com/DataDog/datadog-saist/internal/model

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the binary with version info
	@echo "Building $(TARGET_BIN)..."
	@go build -o $(TARGET_BIN) \
		-ldflags "-X $(CONSTANTS_PATH).Version=$(VERSION) -X $(CONSTANTS_PATH).SCMCommit=$(COMMIT)" \
		./cmd/datadog-saist

.PHONY: build-release
build-release: ## Build release binary (stripped, smaller size)
	@go build -o $(TARGET_BIN) \
		-ldflags "-s -w -X $(CONSTANTS_PATH).Version=$(VERSION) -X $(CONSTANTS_PATH).SCMCommit=$(COMMIT)" \
		./cmd/datadog-saist

.PHONY: test
test: ## Run all tests
	@go test -race ./...

.PHONY: release-local
release-local: ## Test goreleaser locally (no publish)
	@goreleaser release --snapshot --clean

.PHONY: clean
clean: ## Remove build artifacts
	@rm -rf bin/ dist/

.PHONY: local-dev teardown-local-dev

local-dev: ## Configure Bazel shim for local development
	@echo "Configuring Bazel shim..."
	@if [ ! -d ../dd-source ]; then \
		echo "Error: ../dd-source directory does not exist"; \
		exit 1; \
	fi
	@cp WORKSPACE-disable WORKSPACE
	@cp BUILD.bazel-disable BUILD.bazel
	@cp .bazelrc-disable .bazelrc
	@cp .bazelversion-disable .bazelversion
	@if [ ! -f ../dd-source/user.bazelrc ]; then touch ../dd-source/user.bazelrc; fi
	@OVERRIDE_LINE=$$(printf 'common --override_repository=com_github_datadog_datadog_saist_experiment=%s' "$$(pwd -P)"); \
	if ! grep -qF "$$OVERRIDE_LINE" ../dd-source/user.bazelrc; then \
		echo "$$OVERRIDE_LINE" >> ../dd-source/user.bazelrc; \
		echo "Added repository override to ../dd-source/user.bazelrc"; \
	fi
	@echo "Bazel shim configured."
	@echo "Running gazelle..."
	@bzl run //:gazelle

teardown-local-dev:
	@echo "Removing Bazel shim..."
	@if [ ! -d ../dd-source ]; then \
		echo "Error: ../dd-source directory does not exist"; \
		exit 1; \
	fi
	@rm -f WORKSPACE .bazelrc .bazelversion
	@find . -type f -name 'BUILD.bazel' -delete
	@if [ -f ../dd-source/user.bazelrc ]; then \
		OVERRIDE_LINE=$$(printf 'common --override_repository=com_github_datadog_datadog_saist_experiment=%s' "$$(pwd -P)"); \
		if grep -qxF "$$OVERRIDE_LINE" ../dd-source/user.bazelrc; then \
			grep -vxF "$$OVERRIDE_LINE" ../dd-source/user.bazelrc > ../dd-source/user.bazelrc.tmp || true; \
			mv ../dd-source/user.bazelrc.tmp ../dd-source/user.bazelrc; \
			echo "Removed repository override from ../dd-source/user.bazelrc"; \
		fi; \
	fi
	@echo "Bazel shim removed."
