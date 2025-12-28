#!/usr/bin/env python3

import re

# Read the file
with open('/workspace/spec/modules/payloads_spec.rb', 'r') as f:
    content = f.read()

# Define the payload test to insert
payload_test = """
  context 'multi/malware_dropper' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/multi/malware_dropper'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'multi/malware_dropper'
  end
"""

# Find the insertion point - after multi/meterpreter/reverse_https and before netware/shell/reverse_tcp
pattern = r"(  context 'multi/meterpreter/reverse_https' do.*?  end)\n\n(  context 'netware/shell/reverse_tcp' do)"

# Replace with the original content plus our new test
replacement = r"\1" + payload_test + r"\n\2"

# Perform the replacement
new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

# Check if replacement was successful
if new_content != content:
    # Write the modified content back
    with open('/workspace/spec/modules/payloads_spec.rb', 'w') as f:
        f.write(new_content)
    print("Successfully added malware_dropper payload test")
else:
    print("Failed to find insertion point")