#!/usr/bin/env python3

# Test script to check if we can find the insertion point
with open('/workspace/spec/modules/payloads_spec.rb', 'r') as f:
    lines = f.readlines()

# Find the insertion point
insertion_point = None
for i, line in enumerate(lines):
    if "context 'multi/meterpreter/reverse_http'" in line:
        insertion_point = i
        print(f"Found insertion point at line {i+1}: {line.strip()}")
        # Show context around the insertion point
        for j in range(max(0, i-3), min(len(lines), i+3)):
            marker = " >>> " if j == i else "     "
            print(f"{marker}Line {j+1}: {lines[j].rstrip()}")
        break

if insertion_point is None:
    print("Could not find insertion point")
else:
    print(f"\nWill insert malware_dropper test before line {insertion_point+1}")