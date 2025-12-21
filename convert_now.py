#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# Change to workspace and add to path
workspace = Path("/workspace")
os.chdir(workspace)
sys.path.insert(0, str(workspace))

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")

# Import and execute the converter
from batch_ruby_to_python_converter import BatchRubyToPythonConverter

converter = BatchRubyToPythonConverter("/workspace", False)
converter.run_batch_conversion()

print("🎉 PYTHON WINS! 🐍")