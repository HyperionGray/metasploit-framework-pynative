#!/bin/bash

echo "Ruby to Python Migration - Round 5: FIGHT!"
echo "=========================================="

# First run discovery to see what we're working with
echo "Step 1: Running discovery..."
cd /workspace
python3 execute_ruby_to_python_migration.py --dry-run

echo ""
echo "Dry run completed. Press Enter to continue with actual migration, or Ctrl+C to abort..."
read -p ""

echo "Step 2: Executing actual migration..."
python3 execute_ruby_to_python_migration.py

echo ""
echo "Migration completed! Check the results above."