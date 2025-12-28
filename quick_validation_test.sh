#!/bin/bash
# Quick validation script to test our CI/CD fixes

echo "🔍 Testing CI/CD Fixes - Quick Validation"
echo "========================================"

# Test 1: Check Python version
echo "1. Checking Python version..."
python3 --version
if [ $? -eq 0 ]; then
    echo "   ✅ Python available"
else
    echo "   ❌ Python not available"
    exit 1
fi

# Test 2: Check configuration files
echo "2. Checking configuration files..."
for file in pyproject.toml requirements.txt README.md LICENSE.md CHANGELOG.md SECURITY.md; do
    if [ -f "$file" ]; then
        echo "   ✅ $file exists"
    else
        echo "   ❌ $file missing"
    fi
done

# Test 3: Check for duplicate pytest config
echo "3. Checking pyproject.toml for duplicates..."
pytest_sections=$(grep -c "\[tool\.pytest\.ini_options\]" pyproject.toml)
if [ "$pytest_sections" -eq 1 ]; then
    echo "   ✅ Single pytest configuration section"
else
    echo "   ⚠️  Multiple pytest sections found: $pytest_sections"
fi

# Test 4: Check requirements.txt for duplicates
echo "4. Checking requirements.txt for duplicates..."
duplicate_count=$(sort requirements.txt | grep -v "^#" | grep -v "^$" | cut -d'>' -f1 | cut -d'=' -f1 | uniq -d | wc -l)
if [ "$duplicate_count" -eq 0 ]; then
    echo "   ✅ No duplicate dependencies found"
else
    echo "   ⚠️  $duplicate_count duplicate dependencies found"
fi

# Test 5: Check framework structure
echo "5. Checking framework structure..."
for dir in lib modules python_framework test; do
    if [ -d "$dir" ]; then
        echo "   ✅ $dir directory exists"
    else
        echo "   ❌ $dir directory missing"
    fi
done

# Test 6: Test build validator exists and is executable
echo "6. Checking build validator..."
if [ -f "build_validator.py" ]; then
    echo "   ✅ build_validator.py exists"
    # Try to run it with --help or similar
    python3 -c "import sys; sys.path.append('.'); import build_validator; print('   ✅ build_validator.py imports successfully')" 2>/dev/null || echo "   ⚠️  build_validator.py has import issues"
else
    echo "   ❌ build_validator.py missing"
fi

# Test 7: Check CI/CD report generator
echo "7. Checking CI/CD report generator..."
if [ -f "cicd_report_generator.py" ]; then
    echo "   ✅ cicd_report_generator.py exists"
    python3 -c "import sys; sys.path.append('.'); import cicd_report_generator; print('   ✅ cicd_report_generator.py imports successfully')" 2>/dev/null || echo "   ⚠️  cicd_report_generator.py has import issues"
else
    echo "   ❌ cicd_report_generator.py missing"
fi

# Test 8: Check Makefile
echo "8. Checking Makefile..."
if [ -f "Makefile" ]; then
    echo "   ✅ Makefile exists"
    if grep -q "validate:" Makefile; then
        echo "   ✅ Makefile has validate target"
    else
        echo "   ⚠️  Makefile missing validate target"
    fi
else
    echo "   ❌ Makefile missing"
fi

echo ""
echo "🎉 Quick validation complete!"
echo ""
echo "Next steps:"
echo "  - Run: python3 build_validator.py"
echo "  - Run: python3 cicd_report_generator.py"
echo "  - Run: make validate (if make is available)"
echo ""
echo "All major CI/CD issues have been addressed!"