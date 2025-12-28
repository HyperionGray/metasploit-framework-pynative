#!/usr/bin/env python3

import sys
import os

# Add the lib directory to Python path
lib_path = os.path.join(os.path.dirname(__file__), 'lib')
sys.path.insert(0, lib_path)

print(f"Added to Python path: {lib_path}")
print(f"Current working directory: {os.getcwd()}")
print(f"Python path: {sys.path[:3]}...")

print("\nTesting basic msf package import...")

try:
    import msf
    print("✓ Successfully imported msf package")
    print(f"MSF package location: {msf.__file__}")
    print(f"MSF package contents: {dir(msf)}")
except ImportError as e:
    print(f"✗ MSF package import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\nTesting framework import...")

try:
    from msf import framework
    print("✓ Successfully imported framework from msf")
    print(f"Framework type: {type(framework)}")
    
    if hasattr(framework, 'version'):
        print(f"Framework version: {framework.version}")
    else:
        print("Framework object doesn't have version attribute")
        print(f"Framework attributes: {dir(framework)}")
        
except ImportError as e:
    print(f"✗ Framework import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n🎉 All imports successful!")