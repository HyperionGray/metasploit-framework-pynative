#!/usr/bin/env python3
import subprocess
import sys
import os

os.chdir('/workspace')
result = subprocess.run([sys.executable, 'direct_execution.py'])
sys.exit(result.returncode)