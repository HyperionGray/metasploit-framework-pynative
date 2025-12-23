#!/bin/bash

echo "Checking for shell arithmetic operations in workflow files..."
echo "============================================================"

# Search for arithmetic operations
echo "1. Arithmetic operations \$((...))"
grep -r '\$((.*))' .github/workflows/ || echo "No arithmetic operations found"

echo ""
echo "2. Variable assignments with command substitution and fallback"
grep -r '\$([^)]*||[^)]*echo[^)]*0[^)]*)'  .github/workflows/ || echo "No problematic patterns found"

echo ""
echo "3. Comparisons with variables that might be uninitialized"
grep -r '\[ *\$[a-zA-Z_][a-zA-Z0-9_]* *-[gl]t' .github/workflows/ || echo "No direct variable comparisons found"

echo ""
echo "4. Any remaining copilot-cli-action references"
grep -r 'copilot-cli-action' .github/workflows/ || echo "No copilot-cli-action references found"

echo ""
echo "Check complete."