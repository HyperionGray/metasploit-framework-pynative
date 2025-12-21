#!/usr/bin/env python3

import subprocess
import sys
import os

# Execute the final Ruby vs Python fight
os.chdir('/workspace')
result = subprocess.run([sys.executable, 'execute_ruby_python_fight.py'])
sys.exit(result.returncode)