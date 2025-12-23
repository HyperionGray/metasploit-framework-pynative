#!/bin/bash
cd /workspace
echo "Searching for comparison operations that might have unquoted variables..."
echo "1. -lt comparisons:"
grep -r ' -lt ' .github/workflows/ 2>/dev/null || echo "None found"
echo ""
echo "2. -gt comparisons:"
grep -r ' -gt ' .github/workflows/ 2>/dev/null || echo "None found"
echo ""
echo "3. -eq comparisons:"
grep -r ' -eq ' .github/workflows/ 2>/dev/null || echo "None found"
echo ""
echo "4. -ne comparisons:"
grep -r ' -ne ' .github/workflows/ 2>/dev/null || echo "None found"