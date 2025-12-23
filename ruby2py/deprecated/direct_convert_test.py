#!/usr/bin/env python3
"""Direct test of the conversion"""

import os
import sys

# Add the workspace to Python path
sys.path.insert(0, '/workspace')

# Import the converter
from convert_single_exploit import MetasploitRubyToPythonConverter

def test_conversion():
    """Test the conversion process"""
    
    # Initialize converter
    converter = MetasploitRubyToPythonConverter()
    
    # Test file
    ruby_file = '/workspace/modules/exploits/linux/http/apache_airflow_dag_rce.rb'
    
    print(f"Converting: {ruby_file}")
    
    try:
        # Convert the file
        python_content = converter.convert_ruby_file_to_python(ruby_file)
        
        # Write output
        output_file = '/workspace/converted_apache_airflow_dag_rce.py'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(python_content)
        
        print(f"✓ Conversion successful!")
        print(f"✓ Output written to: {output_file}")
        
        # Show first 30 lines
        lines = python_content.split('\n')
        print(f"\nFirst 30 lines of converted code:")
        print("-" * 50)
        for i, line in enumerate(lines[:30], 1):
            print(f"{i:2d}: {line}")
        
        print(f"\nTotal lines: {len(lines)}")
        
        return True
        
    except Exception as e:
        print(f"✗ Conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    test_conversion()