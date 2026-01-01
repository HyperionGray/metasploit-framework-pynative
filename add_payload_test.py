#!/usr/bin/env python3

# Script to add the missing malware_dropper payload test

import re

# Read the file
with open('/workspace/spec/modules/payloads_spec.rb', 'r') as f:
    content = f.read()

# Find the insertion point (after multi/meterpreter/reverse_https)
pattern = r"(  context 'multi/meterpreter/reverse_https' do.*?  end)\n\n(  context 'netware/shell/reverse_tcp' do)"

# The replacement text
replacement = r"""\1

  context 'multi/malware_dropper' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/multi/malware_dropper'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'multi/malware_dropper'
  end

\2"""

# Perform the replacement
new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

# Write back to file
with open('/workspace/spec/modules/payloads_spec.rb', 'w') as f:
    f.write(new_content)

print("Successfully added malware_dropper payload test")