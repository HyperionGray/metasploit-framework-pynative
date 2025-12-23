#!/usr/bin/env python3

# Direct execution without subprocess
import os
import sys

os.chdir('/workspace')
sys.path.insert(0, '/workspace')

# Execute the ruby killer directly
exec(open('/workspace/ruby_killer_execute.py').read())