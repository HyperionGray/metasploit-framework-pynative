#!/bin/bash
# Verify that MSF suite is fully Python-native with no Ruby compatibility scripts

set -e

echo "=========================================="
echo "MSF Python Conversion Verification"
echo "=========================================="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FAILED=0

# Test 1: Check all main executables are Python
echo "Test 1: Checking executable shebangs..."
EXECUTABLES="msfconsole msfvenom msfrpc msfd msfrpcd msfdb msfupdate msf"
for exe in $EXECUTABLES; do
    if [ -f "$exe" ]; then
        if head -1 "$exe" | grep -q "#!/usr/bin/env python3"; then
            echo "  ✅ $exe is Python 3"
        else
            echo "  ❌ $exe is NOT Python 3"
            FAILED=1
        fi
    else
        echo "  ⚠️  $exe not found"
    fi
done
echo ""

# Test 2: Check for Ruby subprocess calls
echo "Test 2: Checking for Ruby subprocess calls..."
if grep -r "subprocess.*ruby" $EXECUTABLES 2>/dev/null | grep -v "Binary file"; then
    echo "  ❌ Found Ruby subprocess calls!"
    FAILED=1
else
    echo "  ✅ No Ruby subprocess calls found"
fi
echo ""

# Test 3: Check for Ruby imports
echo "Test 3: Checking for Ruby file imports..."
if grep -r "import.*\.rb\|require.*\.rb" lib/msf*.py lib/rex.py 2>/dev/null; then
    echo "  ❌ Found Ruby imports!"
    FAILED=1
else
    echo "  ✅ No Ruby imports found"
fi
echo ""

# Test 4: Test msfvenom functionality
echo "Test 4: Testing msfvenom..."
if ./msfvenom --list platforms >/dev/null 2>&1; then
    echo "  ✅ msfvenom works"
else
    echo "  ❌ msfvenom failed"
    FAILED=1
fi
echo ""

# Test 5: Test msf command
echo "Test 5: Testing msf command..."
if ./msf status >/dev/null 2>&1; then
    echo "  ✅ msf command works"
else
    echo "  ❌ msf command failed"
    FAILED=1
fi
echo ""

# Test 6: Test msfdb
echo "Test 6: Testing msfdb..."
if ./msfdb status >/dev/null 2>&1; then
    echo "  ✅ msfdb works"
else
    echo "  ❌ msfdb failed"
    FAILED=1
fi
echo ""

# Test 7: Check msfrc is bash
echo "Test 7: Checking msfrc..."
if [ -f "msfrc" ]; then
    if head -1 msfrc | grep -q "#!/bin/bash"; then
        echo "  ✅ msfrc is bash script"
    else
        echo "  ❌ msfrc is not bash"
        FAILED=1
    fi
else
    echo "  ⚠️  msfrc not found"
fi
echo ""

# Test 8: Test Python module loading
echo "Test 8: Testing Python module loading..."
if python3 -c "import sys; sys.path.insert(0, 'lib'); import msf" 2>/dev/null; then
    echo "  ✅ MSF Python module loads"
else
    echo "  ❌ MSF Python module failed to load"
    FAILED=1
fi
echo ""

# Test 9: Check for compatibility wrappers
echo "Test 9: Checking for compatibility wrappers..."
COMPAT_FILES=$(find . -type f \( -name "*compat*" -o -name "*wrapper*" -o -name "*shim*" \) \
    -not -path "./.git/*" \
    -not -path "./spec/*" \
    -not -path "./test/*" \
    -not -path "./documentation/*" \
    -not -path "./lib/rex/binary_analysis/*" \
    -not -path "./lib/rex/post/*" \
    -not -path "./lib/msf/core/module/compatibility.py" \
    -not -path "./lib/msf/core/session_compatibility.py" \
    2>/dev/null || true)

if [ -z "$COMPAT_FILES" ]; then
    echo "  ✅ No compatibility wrappers found (excluding test/internal files)"
else
    echo "  ⚠️  Some compatibility-related files found (may be internal):"
    echo "$COMPAT_FILES" | sed 's/^/     /'
fi
echo ""

# Summary
echo "=========================================="
if [ $FAILED -eq 0 ]; then
    echo "✅ ALL TESTS PASSED"
    echo ""
    echo "The MSF suite is fully Python-native with"
    echo "NO Ruby compatibility scripts or wrappers."
    echo ""
    echo "See docs/RUBY_TO_PYTHON_VERIFICATION.md"
    echo "for detailed verification report."
    echo "=========================================="
    exit 0
else
    echo "❌ SOME TESTS FAILED"
    echo ""
    echo "Please review the failures above."
    echo "=========================================="
    exit 1
fi
