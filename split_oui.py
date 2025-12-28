#!/usr/bin/env python3

# Script to split the large OUI file into smaller chunks
# This will read the original oui.rb file and split the OUI_LIST hash
# into separate files based on the first character of the MAC address

import os
import re

# Read the original file
original_file = '/workspace/lib/rex/oui.rb'
with open(original_file, 'r') as f:
    lines = f.readlines()

# Find the start and end of the OUI_LIST hash
start_idx = None
end_idx = None
for i, line in enumerate(lines):
    if 'OUI_LIST = {' in line:
        start_idx = i
    elif line.strip() == '}' and start_idx is not None:
        end_idx = i
        break

# Parse the entries
entries = {}
for i in range(start_idx + 1, end_idx):
    line = lines[i].strip()
    if not line:
        continue
    
    # Match lines like: "000000" => ["Xerox", "XEROX CORPORATION"],
    match = re.match(r'"([0-9A-F]{6})" => \[(.*?)\],?$', line)
    if match:
        mac = match.group(1)
        data = match.group(2)
        first_char = mac[0]
        if first_char not in entries:
            entries[first_char] = []
        entries[first_char].append((mac, data))

# Create directory for split files
os.makedirs('/workspace/lib/rex/oui', exist_ok=True)

# Generate split files
for first_char, mac_entries in entries.items():
    filename = f"/workspace/lib/rex/oui/data_{first_char.lower()}.rb"
    
    with open(filename, 'w') as f:
        f.write("# -*- coding: binary -*-\n")
        f.write("\n")
        f.write("module Rex\n")
        f.write("module Oui\n")
        f.write("\n")
        f.write(f"  # OUI data for MAC addresses starting with {first_char}\n")
        f.write(f"  OUI_DATA_{first_char} = {{\n")
        
        for mac, data in mac_entries:
            f.write(f'    "{mac}" => [{data}],\n')
        
        f.write("  }\n")
        f.write("\n")
        f.write("end\n")
        f.write("end\n")
    
    print(f"Created {filename} with {len(mac_entries)} entries")

print("Split complete!")