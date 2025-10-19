# Makefile wrapper for mise
# This Makefile delegates all commands to mise for consistency
# All task definitions are now in .mise.toml

.PHONY: check-mise help all install install_deps install_dev clean format format_check lint lint_fix typecheck check test test_quick test_coverage test_unit test_integration test_file shell audit enforce example build version

# Check if mise is installed
check-mise:
	@command -v mise >/dev/null 2>&1 || { \
		echo ""; \
		echo "==============================================="; \
		echo "ERROR: mise is not installed!"; \
		echo "==============================================="; \
		echo ""; \
		echo "This project uses mise for task management."; \
		echo "Please install mise to continue:"; \
		echo ""; \
		echo "  curl https://mise.run | sh"; \
		echo ""; \
		echo "Or visit: https://mise.jdx.dev/getting-started.html"; \
		echo ""; \
		echo "After installation, run:"; \
		echo "  mise install"; \
		echo "  mise run <task>"; \
		echo ""; \
		echo "To see available tasks:"; \
		echo "  mise tasks"; \
		echo ""; \
		exit 1; \
	}

# Help command
help: check-mise
	@echo "This Makefile is a wrapper for mise."
	@echo "All tasks are defined in .mise.toml"
	@echo ""
	@echo "Available commands:"
	@echo "  make <task>        - Run a mise task"
	@echo "  mise tasks         - List all available tasks"
	@echo "  mise run <task>    - Run a task directly with mise"
	@echo ""
	@mise tasks

# Main workflow
all: check-mise
	@mise run all

# Installation tasks
install: check-mise
	@mise run install

install_deps: check-mise
	@mise run install_deps

install_dev: check-mise
	@mise run install_dev

clean: check-mise
	@mise run clean

# Code quality
format: check-mise
	@mise run format

format_check: check-mise
	@mise run format_check

lint: check-mise
	@mise run lint

lint_fix: check-mise
	@mise run lint_fix

typecheck: check-mise
	@mise run typecheck

check: check-mise
	@mise run check

# Testing
test: check-mise
	@mise run test

test_quick: check-mise
	@mise run test_quick

test_coverage: check-mise
	@mise run test_coverage

test_unit: check-mise
	@mise run test_unit

test_integration: check-mise
	@mise run test_integration

test_file: check-mise
	@mise run test_file file=$(file)

# Development
shell: check-mise
	@mise run shell

audit: check-mise
	@mise run audit policy=$(policy) devices=$(devices)

enforce: check-mise
	@mise run enforce policy=$(policy) devices=$(devices)

example: check-mise
	@mise run example

# Utilities
build: check-mise
	@mise run build

version: check-mise
	@mise run version
