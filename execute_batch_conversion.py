#!/usr/bin/env python3
"""Execute batch conversion directly"""

import sys
import os

# Add workspace to path
sys.path.insert(0, '/workspace')

# Import and run the converter
from batch_ruby_to_python_converter import BatchRubyToPythonConverter

def main():
    print("Executing batch Ruby to Python conversion...")
    
    # Create converter instance (dry run first)
    converter = BatchRubyToPythonConverter(workspace_dir='/workspace', dry_run=True)
    
    print("Running DRY RUN first...")
    converter.run_batch_conversion()
    
    print("\n" + "="*60)
    print("DRY RUN COMPLETED")
    print("="*60)
    
    # Now run actual conversion on a limited set
    print("\nRunning ACTUAL CONVERSION on first 5 post-2020 files...")
    converter_real = BatchRubyToPythonConverter(workspace_dir='/workspace', dry_run=False)
    
    # Find files and convert first few
    ruby_files = converter_real.find_ruby_exploit_files()
    converted_count = 0
    
    for ruby_file in ruby_files:
        if converted_count >= 5:  # Limit to first 5 files
            break
            
        if converter_real.is_post_2020_file(ruby_file):
            python_file = ruby_file.with_suffix('.py')
            if not python_file.exists():  # Don't overwrite existing
                print(f"\nConverting: {ruby_file.relative_to(converter_real.workspace_dir)}")
                if converter_real.convert_file(ruby_file):
                    converted_count += 1
                    print(f"  ✓ Successfully converted #{converted_count}")
                else:
                    print(f"  ✗ Failed to convert")
    
    print(f"\nCompleted conversion of {converted_count} files")

if __name__ == '__main__':
    main()