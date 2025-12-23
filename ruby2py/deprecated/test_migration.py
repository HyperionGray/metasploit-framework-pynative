#!/usr/bin/env python3
"""
Test script to run the migration and see what files would be processed
"""

import sys
import os
sys.path.insert(0, '/workspace')

from migrate_ruby_to_python import RubyToPythonMigrator

# Create migrator instance
migrator = RubyToPythonMigrator(workspace_dir='/workspace', dry_run=True, verbose=True)

# Find Ruby files
ruby_files = migrator.find_ruby_files()

print(f"Found {len(ruby_files)} Ruby files")
print("\nFirst 20 Ruby files:")
for i, filepath in enumerate(ruby_files[:20]):
    rel_path = filepath.relative_to(migrator.workspace_dir)
    classification = migrator.classify_file(filepath)
    print(f"{i+1:2d}. {rel_path} [{classification}]")

print(f"\n... and {len(ruby_files) - 20} more files")

# Show classification summary
classifications = {}
for filepath in ruby_files:
    classification = migrator.classify_file(filepath)
    classifications[classification] = classifications.get(classification, 0) + 1

print("\nClassification Summary:")
for classification, count in classifications.items():
    print(f"  {classification}: {count} files")