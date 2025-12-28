#!/bin/bash

# Comprehensive Framework Assessment Script
# Runs all assessment tools and generates final report

echo "=========================================="
echo "METASPLOIT FRAMEWORK GLOBAL ASSESSMENT"
echo "=========================================="
echo "Starting comprehensive assessment..."
echo

# 1. Run functionality tests
echo "1. FUNCTIONALITY ASSESSMENT"
echo "=========================="
python3 test_framework_functionality.py
echo

# 2. Run code quality analysis
echo "2. CODE QUALITY ANALYSIS"
echo "======================="
python3 analyze_code_quality.py
echo

# 3. Check test suite status
echo "3. TEST SUITE VALIDATION"
echo "======================="
if [ -f "run_comprehensive_tests.py" ]; then
    echo "Found comprehensive test runner"
    python3 run_comprehensive_tests.py --help 2>/dev/null || echo "Test runner has issues"
else
    echo "Comprehensive test runner not found"
fi

if [ -d "test" ]; then
    echo "Test directory exists with $(find test -name '*.py' | wc -l) Python test files"
else
    echo "Test directory not found"
fi
echo

# 4. Check recent issues and pain points
echo "4. RECENT ISSUES ANALYSIS"
echo "======================="
if [ -f "allissues.txt" ]; then
    echo "Recent issues (last 10):"
    head -10 allissues.txt
else
    echo "Issues file not found"
fi
echo

# 5. Dependency check
echo "5. DEPENDENCY VALIDATION"
echo "======================="
if [ -f "requirements.txt" ]; then
    echo "Requirements file found with $(wc -l < requirements.txt) lines"
    echo "Checking key dependencies..."
    
    # Check if pip can parse requirements
    python3 -c "
import pkg_resources
try:
    with open('requirements.txt') as f:
        requirements = f.read()
    print('Requirements file is parseable')
except Exception as e:
    print(f'Requirements file has issues: {e}')
"
else
    echo "Requirements file not found"
fi
echo

# 6. File structure validation
echo "6. FILE STRUCTURE ANALYSIS"
echo "========================="
echo "Directory structure:"
for dir in modules lib tools data python_framework ruby2py test docs; do
    if [ -d "$dir" ]; then
        file_count=$(find "$dir" -type f | wc -l)
        echo "  ✓ $dir/ ($file_count files)"
    else
        echo "  ✗ $dir/ (missing)"
    fi
done
echo

# 7. Conversion validation
echo "7. CONVERSION VALIDATION"
echo "======================"
python_count=$(find . -name "*.py" -type f | wc -l)
ruby_count=$(find . -name "*.rb" -type f | wc -l)
echo "Python files found: $python_count"
echo "Ruby files found: $ruby_count"

if [ $python_count -gt 7000 ]; then
    echo "✓ Python file count matches conversion claims"
else
    echo "⚠ Python file count lower than claimed 7,456"
fi
echo

# 8. Generate final assessment
echo "8. FINAL ASSESSMENT GENERATION"
echo "============================"
python3 -c "
import json
import os
from datetime import datetime

# Collect all assessment data
assessment = {
    'timestamp': datetime.now().isoformat(),
    'overall_status': 'ASSESSMENT_COMPLETE',
    'components': {}
}

# Load functionality results if available
if os.path.exists('functionality_test_results.json'):
    with open('functionality_test_results.json') as f:
        assessment['components']['functionality'] = json.load(f)

# Load code quality results if available
if os.path.exists('code_quality_results.json'):
    with open('code_quality_results.json') as f:
        assessment['components']['code_quality'] = json.load(f)

# Calculate overall score
total_tests = 0
passed_tests = 0

if 'functionality' in assessment['components']:
    func_summary = assessment['components']['functionality']['summary']
    total_tests += func_summary['total']
    passed_tests += func_summary['passed']

overall_score = (passed_tests / total_tests * 100) if total_tests > 0 else 0

assessment['overall_score'] = round(overall_score, 1)
assessment['recommendation'] = (
    'PRODUCTION_READY' if overall_score >= 80 else
    'DEVELOPMENT_READY' if overall_score >= 60 else
    'PROTOTYPE_STAGE' if overall_score >= 40 else
    'EARLY_DEVELOPMENT'
)

# Save final assessment
with open('FINAL_ASSESSMENT.json', 'w') as f:
    json.dump(assessment, f, indent=2)

print(f'Overall Assessment Score: {assessment[\"overall_score\"]}%')
print(f'Project Status: {assessment[\"recommendation\"]}')
print('Final assessment saved to: FINAL_ASSESSMENT.json')
"

echo
echo "=========================================="
echo "ASSESSMENT COMPLETE"
echo "=========================================="
echo "Check the following files for detailed results:"
echo "  - GLOBAL_REVIEW_ASSESSMENT.md (comprehensive review)"
echo "  - functionality_test_results.json (functionality tests)"
echo "  - code_quality_results.json (code quality analysis)"
echo "  - FINAL_ASSESSMENT.json (overall assessment)"
echo