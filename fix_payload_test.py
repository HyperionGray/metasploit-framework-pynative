#!/usr/bin/env python3

# Script to add the missing malware_dropper payload test

def add_malware_dropper_test():
    file_path = '/workspace/spec/modules/payloads_spec.rb'
    
    # Read the entire file
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Find the insertion point (after multi/meterpreter/reverse_https test)
    target_line = "                          reference_name: 'multi/meterpreter/reverse_https'\n  end\n"
    
    if target_line not in content:
        print("Target insertion point not found!")
        return False
    
    # The test definition to insert
    test_definition = """
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
    
    # Replace the target with target + test definition
    new_content = content.replace(
        target_line,
        target_line + test_definition
    )
    
    # Write the modified content back
    with open(file_path, 'w') as f:
        f.write(new_content)
    
    print("Successfully added malware_dropper payload test")
    return True

if __name__ == "__main__":
    add_malware_dropper_test()