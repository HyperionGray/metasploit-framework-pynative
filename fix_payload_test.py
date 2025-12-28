#!/usr/bin/env python3

# Script to add the missing malware_dropper payload test to payloads_spec.rb

# Read the current file
with open('/workspace/spec/modules/payloads_spec.rb', 'r') as f:
    lines = f.readlines()

# Find the insertion point (after mainframe/shell_reverse_tcp, before multi/meterpreter/reverse_http)
insertion_point = None
for i, line in enumerate(lines):
    if "context 'multi/meterpreter/reverse_http'" in line:
        insertion_point = i
        break

if insertion_point is None:
    print("Could not find insertion point")
    exit(1)

# The test context to insert
new_test_context = [
    "  context 'multi/malware_dropper' do\n",
    "    it_should_behave_like 'payload cached size is consistent',\n",
    "                          ancestor_reference_names: [\n",
    "                              'singles/multi/malware_dropper'\n",
    "                          ],\n",
    "                          dynamic_size: false,\n",
    "                          modules_pathname: modules_pathname,\n",
    "                          reference_name: 'multi/malware_dropper'\n",
    "  end\n",
    "\n"
]

# Insert the new test context
lines[insertion_point:insertion_point] = new_test_context

# Write the modified content back
with open('/workspace/spec/modules/payloads_spec.rb', 'w') as f:
    f.writelines(lines)

print("Successfully added malware_dropper payload test")