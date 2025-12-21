#!/usr/bin/env python3

import os
import sys

os.chdir('/workspace')
sys.path.insert(0, '/workspace')

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")

from batch_ruby_to_python_converter import BatchRubyToPythonConverter
converter = BatchRubyToPythonConverter("/workspace", False)
converter.run_batch_conversion()

print("🎉 PYTHON WINS! 🐍")