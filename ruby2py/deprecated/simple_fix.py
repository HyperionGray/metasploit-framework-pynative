#!/usr/bin/env python3

# Read the current file
with open('/workspace/spec/modules/payloads_spec.rb', 'r') as f:
    content = f.read()

# Find the insertion point (before the first multi/meterpreter test)
target_line = "  context 'multi/meterpreter/reverse_http' do"
insertion_point = content.find(target_line)

if insertion_point == -1:
    print("Could not find insertion point")
    exit(1)

# The new payload test definition
new_payload_test = """  context 'multi/malware_dropper' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/multi/malware_dropper'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'multi/malware_dropper'
  end

"""

# Insert the new test before the meterpreter test
new_content = content[:insertion_point] + new_payload_test + content[insertion_point:]

# Write the modified file
with open('/workspace/spec/modules/payloads_spec.rb', 'w') as f:
    f.write(new_content)

print("Successfully added malware_dropper payload test")