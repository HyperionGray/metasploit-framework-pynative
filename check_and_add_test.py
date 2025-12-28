#!/usr/bin/env python3

# Check if malware_dropper test already exists
with open('/workspace/spec/modules/payloads_spec.rb', 'r') as f:
    content = f.read()

if 'malware_dropper' in content:
    print("malware_dropper test already exists")
else:
    print("malware_dropper test does not exist - need to add it")
    
    # Find the insertion point
    lines = content.split('\n')
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
        print(f"Found insertion point at line {insert_index}")
        print(f"Line content: '{lines[insert_index-1]}'")
        print(f"Next line: '{lines[insert_index]}'")
        
        # Insert the new test
        new_test_lines = [
            "  context 'multi/malware_dropper' do",
            "    it_should_behave_like 'payload cached size is consistent',",
            "                          ancestor_reference_names: [",
            "                              'singles/multi/malware_dropper'",
            "                          ],",
            "                          dynamic_size: false,",
            "                          modules_pathname: modules_pathname,",
            "                          reference_name: 'multi/malware_dropper'",
            "  end",
            ""
        ]
        
        # Insert the new lines
        lines[insert_index:insert_index] = new_test_lines
        
        # Write back to file
        with open('/workspace/spec/modules/payloads_spec.rb', 'w') as f:
            f.write('\n'.join(lines))
        
        print("Successfully added malware_dropper payload test")
    else:
        print("Could not find insertion point")