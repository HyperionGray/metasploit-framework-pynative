#!/bin/bash
cd /workspace
echo "Searching for arithmetic operations in workflow files..."
grep -r '\$((.*))' .github/workflows/ 2>/dev/null || echo "No arithmetic operations found"
echo ""
echo "Searching for variable comparisons..."
grep -r '\[ .*\$.*-[gl]t' .github/workflows/ 2>/dev/null || echo "No variable comparisons found"
echo ""
echo "Searching for command substitution with fallback..."
grep -r 'echo.*0.*))' .github/workflows/ 2>/dev/null || echo "No command substitution patterns found"