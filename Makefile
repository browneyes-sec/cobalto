# =============================================================================
# Cobalto SOC/MDR — Makefile
# =============================================================================
# Development workflow targets for the cobalto platform.
# =============================================================================

.PHONY: help bench bench-single bench-baseline lint test test-unit test-integration test-e2e clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Benchmarking ──────────────────────────────────────────────────────────

bench: ## Run all performance benchmarks
	./scripts/run-benchmarks.sh

bench-single: ## Run a single benchmark test: make bench-single TEST=auth_burst
	./scripts/run-benchmarks.sh --test $(TEST)

bench-baseline: ## Update baseline with current benchmark results
	./scripts/run-benchmarks.sh --baseline

bench-ci: ## Run benchmarks in CI mode (fail on regression)
	./scripts/run-benchmarks.sh --ci

# ── Linting ───────────────────────────────────────────────────────────────

lint: ## Run all linters
	ruff check services/langgraph-agent/
	yamllint kubernetes/ --no-warnings -d '{extends: relaxed, rules: {line-length: {max: 120}}}' || true

lint-fix: ## Auto-fix lint issues
	ruff check --fix services/langgraph-agent/

# ── Testing ───────────────────────────────────────────────────────────────

test: ## Run all tests (unit + integration)
	PYTHONPATH=services/langgraph-agent python3 -m pytest \
		tests/unit/ tests/integration/ \
		-v --tb=short -W ignore::DeprecationWarning

test-unit: ## Run unit tests only
	PYTHONPATH=services/langgraph-agent python3 -m pytest \
		tests/unit/ -v --tb=short -W ignore::DeprecationWarning

test-integration: ## Run integration tests only
	PYTHONPATH=services/langgraph-agent python3 -m pytest \
		tests/integration/ -v --tb=short -W ignore::DeprecationWarning

test-e2e: ## Run E2E tests (requires running cluster)
	COBALTO_E2E_URL=$(COBALTO_E2E_URL) python3 -m pytest \
		tests/e2e/ -v --tb=long -W ignore::DeprecationWarning

test-coverage: ## Run all tests with coverage report
	PYTHONPATH=services/langgraph-agent python3 -m pytest \
		tests/unit/ tests/integration/ \
		-v --tb=short \
		--cov=services/langgraph-agent \
		--cov-report=term-missing \
		--cov-fail-under=80 \
		-W ignore::DeprecationWarning

# ── Utility ───────────────────────────────────────────────────────────────

clean: ## Clean temporary files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf reports/
