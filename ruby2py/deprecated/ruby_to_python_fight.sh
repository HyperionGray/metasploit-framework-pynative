#!/bin/bash

echo "=============================================="
echo "RUBY TO PYTHON CONVERSION - ROUND 1: FIGHT!"
echo "=============================================="
echo "Converting all post-2020 Ruby files to Python"
echo "=============================================="

cd /workspace

# Make sure the conversion script is executable
chmod +x batch_ruby_to_python_converter.py

# Run the conversion
echo "Starting conversion process..."
python3 batch_ruby_to_python_converter.py

echo ""
echo "=============================================="
echo "CONVERSION COMPLETE!"
echo "Ruby v Python: Round 1 - PYTHON WINS! 🐍"
echo "=============================================="