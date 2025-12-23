#!/usr/bin/env python3
"""Test the conversion of a single Ruby file"""

import sys
import os
sys.path.insert(0, '/workspace')

from convert_single_exploit import MetasploitRubyToPythonConverter

# Test with the Apache Airflow exploit
ruby_file = '/workspace/modules/exploits/linux/http/apache_airflow_dag_rce.rb'
converter = MetasploitRubyToPythonConverter()

try:
    python_content = converter.convert_ruby_file_to_python(ruby_file)
    
    # Write to test output file
    output_file = '/workspace/test_apache_airflow_dag_rce.py'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(python_content)
    
    print(f"Successfully converted {ruby_file}")
    print(f"Output written to {output_file}")
    print("\nFirst 50 lines of converted Python code:")
    print("-" * 60)
    
    lines = python_content.split('\n')
    for i, line in enumerate(lines[:50], 1):
        print(f"{i:2d}: {line}")
    
    if len(lines) > 50:
        print(f"... and {len(lines) - 50} more lines")

except Exception as e:
    print(f"Error converting file: {e}")
    import traceback
    traceback.print_exc()