#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# Setup workspace
workspace = Path("/workspace")
os.chdir(workspace)
sys.path.insert(0, str(workspace))

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("Converting post-2020 Ruby files to Python...")

# Import and run converter
from batch_ruby_to_python_converter import BatchRubyToPythonConverter

converter = BatchRubyToPythonConverter(workspace_dir=str(workspace), dry_run=False)
converter.run_batch_conversion()

print("🎉 PYTHON WINS! 🐍")