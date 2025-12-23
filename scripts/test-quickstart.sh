#!/usr/bin/env bash
# Quick Start Script for Metasploit Framework Testing
# This script helps developers get started with the comprehensive test suite

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if Python is installed
check_python() {
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    print_success "Python 3 is installed: $(python3 --version)"
}

# Check if pip is installed
check_pip() {
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 is not installed"
        exit 1
    fi
    print_success "pip3 is installed: $(pip3 --version)"
}

# Install test dependencies
install_dependencies() {
    print_header "Installing Test Dependencies"
    
    print_info "Installing core testing packages..."
    pip3 install pytest pytest-cov pytest-xdist pytest-timeout pytest-benchmark || {
        print_error "Failed to install core testing packages"
        exit 1
    }
    
    print_info "Installing property-based testing..."
    pip3 install hypothesis faker || {
        print_warning "Failed to install hypothesis (property-based tests will be skipped)"
    }
    
    print_info "Installing test utilities..."
    pip3 install freezegun responses || {
        print_warning "Failed to install test utilities"
    }
    
    print_info "Installing code quality tools..."
    pip3 install flake8 black isort mypy bandit safety || {
        print_warning "Failed to install code quality tools"
    }
    
    print_success "Dependencies installed successfully"
}

# Run a quick smoke test
run_smoke_test() {
    print_header "Running Smoke Test"
    
    # Try to import pytest
    python3 -c "import pytest; print('pytest:', pytest.__version__)" || {
        print_error "pytest not available"
        return 1
    }
    
    # Check if test files exist
    if [ -f "test/test_comprehensive_suite.py" ]; then
        print_success "Test files found"
    else
        print_error "Test files not found"
        return 1
    fi
    
    # Run a simple test
    print_info "Running a simple test..."
    python3 -m pytest test/test_comprehensive_suite.py::TestConfiguration::test_pyproject_toml_exists -v || {
        print_warning "Simple test failed (may need dependencies)"
        return 1
    }
    
    print_success "Smoke test passed"
}

# Display usage information
show_usage() {
    print_header "Comprehensive Test Suite - Quick Start"
    
    echo "Available Commands:"
    echo ""
    echo "  Basic Testing:"
    echo "    ./run_comprehensive_tests.py              Run all tests"
    echo "    ./run_comprehensive_tests.py --verbose    Run with detailed output"
    echo "    ./run_comprehensive_tests.py --quick      Run only fast tests"
    echo ""
    echo "  Category Testing:"
    echo "    ./run_comprehensive_tests.py --categories unit"
    echo "    ./run_comprehensive_tests.py --categories security crypto"
    echo "    ./run_comprehensive_tests.py --categories integration network"
    echo ""
    echo "  Using Make (if available):"
    echo "    make -f Makefile.testing test              Run comprehensive tests"
    echo "    make -f Makefile.testing test-unit         Run unit tests"
    echo "    make -f Makefile.testing test-quick        Run quick tests"
    echo "    make -f Makefile.testing test-coverage     Run with coverage"
    echo ""
    echo "  Using pytest directly:"
    echo "    pytest test/                               Run all test files"
    echo "    pytest test/test_comprehensive_suite.py    Run specific file"
    echo "    pytest -m unit                             Run tests with marker"
    echo "    pytest -k test_name                        Run specific test"
    echo ""
    echo "  Documentation:"
    echo "    cat TESTING_COMPREHENSIVE_GUIDE.md         View complete guide"
    echo "    make -f Makefile.testing help              View all make targets"
    echo ""
}

# Main script
main() {
    print_header "Metasploit Framework Testing - Quick Start"
    
    # Check prerequisites
    check_python
    check_pip
    
    # Ask if user wants to install dependencies
    echo ""
    read -p "Install test dependencies? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_dependencies
    else
        print_info "Skipping dependency installation"
    fi
    
    # Ask if user wants to run smoke test
    echo ""
    read -p "Run smoke test? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        run_smoke_test || print_warning "Smoke test had issues, but continuing..."
    else
        print_info "Skipping smoke test"
    fi
    
    # Show usage
    show_usage
    
    print_header "Setup Complete!"
    print_success "You're ready to run tests!"
    print_info "Start with: ./run_comprehensive_tests.py --verbose"
    print_info "Or read the guide: cat TESTING_COMPREHENSIVE_GUIDE.md"
}

# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
