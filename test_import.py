#!/usr/bin/env python3

import sys
import os

# Add the lib directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

print("Testing MSF framework import...")

try:
    from msf import framework
    print("✓ Successfully imported framework from msf")
    print(f"Framework type: {type(framework)}")
    print(f"Framework version: {framework.version}")
    
    # Test framework functionality
    info = framework.info()
    print("✓ Framework info retrieved:")
    for key, value in info.items():
        print(f"  {key}: {value}")
        
except ImportError as e:
    print(f"✗ Import failed: {e}")
    sys.exit(1)

try:
    from msf.core.framework import Framework
    print("✓ Successfully imported Framework class")
    
    # Create new instance
    fw = Framework()
    print(f"✓ Created new Framework instance: {fw.version}")
    
except ImportError as e:
    print(f"✗ Framework class import failed: {e}")
    sys.exit(1)

print("\nAll imports successful! 🎉")