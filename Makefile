# Makefile for Metasploit Framework Python-native
# Provides easy commands for build validation, testing, and CI/CD operations

.PHONY: help install test lint format validate report clean all

# Default target
help:
	@echo "Metasploit Framework Python-native Build Commands"
	@echo "=================================================="
	@echo ""
	@echo "Available targets:"
	@echo "  install    - Install dependencies"
	@echo "  test       - Run test suite"
	@echo "  lint       - Run code linting"
	@echo "  format     - Format code with black and isort"
	@echo "  validate   - Run comprehensive build validation"
	@echo "  report     - Generate CI/CD status report"
	@echo "  clean      - Clean build artifacts"
	@echo "  all        - Run install, lint, test, and validate"
	@echo ""

# Install dependencies
install:
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "Dependencies installed successfully"

# Run tests
test:
	@echo "Running test suite..."
	python -m pytest test/ -v --tb=short
	@echo "Tests completed"

# Run linting
lint:
	@echo "Running code linting..."
	python -m flake8 python_framework/ lib/ --count --max-line-length=120 || true
	@echo "Linting completed"

# Format code
format:
	@echo "Formatting code..."
	python -m black python_framework/ lib/ --line-length=120 || true
	python -m isort python_framework/ lib/ --profile=black || true
	@echo "Code formatting completed"

# Run build validation
validate:
	@echo "Running comprehensive build validation..."
	python build_validator.py
	@echo "Build validation completed"

# Generate CI/CD report
report:
	@echo "Generating CI/CD status report..."
	python cicd_report_generator.py
	@echo "CI/CD report generated"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage coverage.xml 2>/dev/null || true
	rm -f build_validation_results.json cicd_status_report.md 2>/dev/null || true
	@echo "Build artifacts cleaned"

# Run all checks
all: install lint test validate report
	@echo "All build operations completed successfully"

# Quick validation (without full test suite)
quick-validate:
	@echo "Running quick validation..."
	python build_validator.py
	python -m pytest test/test_comprehensive_suite.py::TestFrameworkCore::test_framework_imports -v
	@echo "Quick validation completed"

# Development setup
dev-setup: install
	@echo "Setting up development environment..."
	pip install pre-commit
	pre-commit install || true
	@echo "Development environment setup completed"