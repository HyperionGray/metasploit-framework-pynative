#!/usr/bin/env python3

import subprocess
import os

# Change to workspace
os.chdir('/workspace')

# Make executable
os.chmod('final_ruby_python_fight.py', 0o755)

# Execute the final fight
subprocess.run(['python3', 'final_ruby_python_fight.py'])