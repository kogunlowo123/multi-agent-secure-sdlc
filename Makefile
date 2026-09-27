.PHONY: help install install-dev format lint test test-unit test-integration test-security \
        coverage docker-build docker-up docker-down migrate semgrep clean

PYTHON := python3
UV := uv
PYTEST := $(UV) run pytest
RUFF := $(UV) run ruff
MYPY := $(UV) run mypy

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	$(UV) sync

install-dev: ## Install development dependencies
	$(UV) sync --extra dev

format: ## Format code with ruff
	$(RUFF) format services/ tests/
	$(RUFF) check --fix services/ tests/

lint: ## Lint code with ruff and mypy
	$(RUFF) check services/ tests/
	$(MYPY) services/ --ignore-missing-imports

test: ## Run all tests
	$(PYTEST) tests/ -v --tb=short

test-unit: ## Run unit tests
	$(PYTEST) tests/unit/ -v --tb=short

test-integration: ## Run integration tests
	$(PYTEST) tests/integration/ -v --tb=short

test-security: ## Run security tests
	$(PYTEST) tests/security/ -v --tb=short

coverage: ## Run tests with coverage report
	$(PYTEST) tests/ --cov=services --cov-report=html --cov-report=term-missing --cov-fail-under=70

docker-build: ## Build all Docker images
	docker compose build

docker-up: ## Start all services
	docker compose up -d

docker-down: ## Stop all services
	docker compose down -v

docker-logs: ## Show service logs
	docker compose logs -f

migrate: ## Run database migrations
	$(UV) run alembic upgrade head

semgrep: ## Run SAST scan with semgrep
	semgrep --config=auto services/ --json | python3 -m json.tool | head -100

clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name dist -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name build -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name ".coverage" -delete 2>/dev/null || true

version: ## Show current version
	@cat VERSION
