#!/usr/bin/env python3

# Simple test to check file access
try:
    with open('/workspace/spec/modules/payloads_spec.rb', 'r') as f:
        content = f.read()
    
    print(f"File size: {len(content)} characters")
    
    if 'malware_dropper' in content:
        print("malware_dropper test already exists")
    else:
        print("malware_dropper test does not exist")
        
    # Check for the reference line
    if "reference_name: 'multi/meterpreter/reverse_https'" in content:
        print("Found reference line for multi/meterpreter/reverse_https")
    else:
        print("Could not find reference line")
        
except Exception as e:
    print(f"Error: {e}")