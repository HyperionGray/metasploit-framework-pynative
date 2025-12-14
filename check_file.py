#!/usr/bin/env python3

# Check the exact content around line 2500 in the payloads_spec.rb file
with open('/workspace/spec/modules/payloads_spec.rb', 'rb') as f:
    lines = f.readlines()
    
print("Lines 2495-2505 (raw bytes):")
for i in range(2494, min(2505, len(lines))):
    line_num = i + 1
    line_content = lines[i]
    print(f"Line {line_num}: {repr(line_content)}")

print("\nLines 2495-2505 (decoded):")
for i in range(2494, min(2505, len(lines))):
    line_num = i + 1
    line_content = lines[i].decode('utf-8', errors='replace')
    print(f"Line {line_num}: {repr(line_content)}")