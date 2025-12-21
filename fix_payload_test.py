#!/usr/bin/env python3

# Script to add the missing payload test to payloads_spec.rb
import os

# Read the current file
with open('/workspace/spec/modules/payloads_spec.rb', 'r') as f:
    lines = f.readlines()

# Find the insertion point (before the first multi/meterpreter test)
insertion_point = None
for i, line in enumerate(lines):
    if "context 'multi/meterpreter/reverse_http'" in line:
        # Insert before this line, but after the previous end
        # Go back to find the previous "end" and insert after it
        for j in range(i - 1, -1, -1):
            if lines[j].strip() == 'end':
                insertion_point = j + 1
                break
        break

if insertion_point is None:
    print("Could not find insertion point")
    exit(1)

print(f"Found insertion point at line {insertion_point + 1}")

# The new payload test definition
new_payload_test = [
    "\n",
    "  context 'multi/malware_dropper' do\n",
    "    it_should_behave_like 'payload cached size is consistent',\n",
    "                          ancestor_reference_names: [\n",
    "                              'singles/multi/malware_dropper'\n",
    "                          ],\n",
    "                          dynamic_size: false,\n",
    "                          modules_pathname: modules_pathname,\n",
    "                          reference_name: 'multi/malware_dropper'\n",
    "  end\n"
]

# Insert the new test
lines[insertion_point:insertion_point] = new_payload_test

# Write the modified file
with open('/workspace/spec/modules/payloads_spec.rb', 'w') as f:
    f.writelines(lines)

print("Successfully added malware_dropper payload test")