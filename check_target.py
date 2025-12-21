#!/usr/bin/env python3

# First, let's check if we can find the target line
with open('/workspace/spec/modules/payloads_spec.rb', 'r') as f:
    lines = f.readlines()

target_line_index = None
for i, line in enumerate(lines):
    if "context 'multi/meterpreter/reverse_http'" in line:
        target_line_index = i
        break

print(f"Target line found at index: {target_line_index}")
if target_line_index is not None:
    print(f"Line content: {lines[target_line_index].strip()}")
    print(f"Previous line: {lines[target_line_index-1].strip()}")
    print(f"Next line: {lines[target_line_index+1].strip()}")