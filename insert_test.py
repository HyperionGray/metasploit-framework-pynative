#!/usr/bin/env python3

# Read all lines from the file
with open('/workspace/spec/modules/payloads_spec.rb', 'r') as f:
    lines = f.readlines()

# Find the line with "context 'multi/meterpreter/reverse_http'"
target_line_index = None
for i, line in enumerate(lines):
    if "context 'multi/meterpreter/reverse_http'" in line:
        target_line_index = i
        break

if target_line_index is None:
    print("Could not find target line")
    exit(1)

print(f"Found target line at index {target_line_index} (line {target_line_index + 1})")

# Create the new test case lines
new_test_lines = [
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

# Insert the new lines before the target line
lines[target_line_index:target_line_index] = new_test_lines

# Write the modified content back to the file
with open('/workspace/spec/modules/payloads_spec.rb', 'w') as f:
    f.writelines(lines)

print("Successfully added malware_dropper payload test")