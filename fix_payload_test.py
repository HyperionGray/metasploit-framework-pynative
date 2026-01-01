#!/usr/bin/env python3

# Script to add the missing malware_dropper payload test

# Read the file
with open('/workspace/spec/modules/payloads_spec.rb', 'r') as f:
    lines = f.readlines()

# Find the line with 'multi/meterpreter/reverse_https' end
insert_index = None
for i, line in enumerate(lines):
    if "reference_name: 'multi/meterpreter/reverse_https'" in line:
        # Find the next 'end' line
        for j in range(i+1, len(lines)):
            if lines[j].strip() == 'end':
                insert_index = j + 2  # Insert after the empty line
                break
        break

if insert_index:
    # Insert the new test
    new_test = [
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
    
    # Insert the new test
    lines[insert_index:insert_index] = new_test
    
    # Write back to file
    with open('/workspace/spec/modules/payloads_spec.rb', 'w') as f:
        f.writelines(lines)
    
    print("Successfully added malware_dropper payload test")
else:
    print("Could not find insertion point")