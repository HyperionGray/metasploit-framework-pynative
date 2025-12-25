#!/usr/bin/env python3

import shutil
import os

# Copy Ruby files to .rb versions
ruby_files = ['msfconsole', 'msfd', 'msfdb', 'msfvenom', 'msfrpc', 'msfrpcd', 'msfupdate']

for file in ruby_files:
    if os.path.exists(file):
        shutil.copy2(file, f"{file}.rb")
        print(f"Copied {file} to {file}.rb")