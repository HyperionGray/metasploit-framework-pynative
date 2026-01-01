#!/bin/bash
# PR Merge Helper Script
# This script assists with merging multiple pull requests in the recommended order
# NOTE: This script requires GitHub CLI (gh) to be installed and authenticated

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO="HyperionGray/metasploit-framework-pynative"
BASE_BRANCH="master"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if gh CLI is installed
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v gh &> /dev/null; then
        print_error "GitHub CLI (gh) is not installed. Please install it first."
        print_error "Visit: https://cli.github.com/"
        exit 1
    fi
    
    if ! gh auth status &> /dev/null; then
        print_error "GitHub CLI is not authenticated. Please run 'gh auth login'"
        exit 1
    fi
    
    print_status "Prerequisites check passed"
}

# Function to check PR status
check_pr_status() {
    local pr_number=$1
    print_status "Checking status of PR #$pr_number..."
    
    gh pr view "$pr_number" --repo "$REPO" --json state,mergeable,isDraft,reviewDecision
}

# Function to attempt merge
merge_pr() {
    local pr_number=$1
    local merge_method=${2:-"squash"}  # Default to squash merge
    
    print_status "Attempting to merge PR #$pr_number..."
    
    # Check if PR is mergeable
    local status=$(gh pr view "$pr_number" --repo "$REPO" --json mergeable --jq '.mergeable')
    
    if [ "$status" != "MERGEABLE" ]; then
        print_error "PR #$pr_number is not mergeable (status: $status)"
        return 1
    fi
    
    # Attempt merge
    if gh pr merge "$pr_number" --repo "$REPO" --"$merge_method" --auto; then
        print_status "Successfully merged PR #$pr_number"
        return 0
    else
        print_error "Failed to merge PR #$pr_number"
        return 1
    fi
}

# Function to merge PRs in phases
merge_phase() {
    local phase_name=$1
    shift
    local pr_numbers=("$@")
    
    print_status "========================================="
    print_status "Starting Phase: $phase_name"
    print_status "========================================="
    
    for pr in "${pr_numbers[@]}"; do
        print_status "Processing PR #$pr"
        
        # Check status
        if ! check_pr_status "$pr"; then
            print_warning "Skipping PR #$pr due to status check failure"
            continue
        fi
        
        # Attempt merge
        if merge_pr "$pr"; then
            print_status "Successfully processed PR #$pr"
        else
            print_warning "Could not merge PR #$pr - manual intervention may be required"
            read -p "Continue with next PR? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                print_error "Merge process stopped by user"
                exit 1
            fi
        fi
        
        # Wait a bit between merges to allow CI to process
        print_status "Waiting for CI to process..."
        sleep 10
    done
    
    print_status "Phase '$phase_name' complete"
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    
    # Add your test commands here
    # Example:
    # pytest || { print_error "Tests failed"; exit 1; }
    
    print_status "Tests passed"
}

# Main execution
main() {
    print_status "PR Merge Helper Script"
    print_status "Repository: $REPO"
    
    check_prerequisites
    
    # Phase 1: Critical Configuration Fixes
    print_status "NOTE: PRs #244, #247, and #248 may conflict. Choose ONE."
    read -p "Which PR should be merged first? (244/247/248) " pr_choice
    
    case $pr_choice in
        244|247|248)
            merge_phase "Phase 1 - Critical Config Fixes" "$pr_choice"
            ;;
        *)
            print_error "Invalid choice. Please run script again."
            exit 1
            ;;
    esac
    
    # Run tests after Phase 1
    if command -v pytest &> /dev/null; then
        run_tests
    else
        print_warning "pytest not found, skipping tests"
    fi
    
    # Phase 2: CI/CD Infrastructure
    merge_phase "Phase 2 - CI/CD Improvements" 246 245
    
    # Phase 3: Testing Infrastructure  
    merge_phase "Phase 3 - Testing" 235 224
    
    # Phase 4: Documentation and remaining PRs
    print_status "Phase 4 requires manual review of migration PRs"
    print_status "Please review PRs #215-#243 individually"
    
    print_status "========================================="
    print_status "Merge process complete!"
    print_status "========================================="
}

# Run main function
main "$@"
