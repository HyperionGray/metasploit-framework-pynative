#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# Add the workspace to Python path
sys.path.insert(0, '/workspace')
os.chdir('/workspace')

# Import and run the discovery directly
try:
    from tools.dev.discover_post_2020_exploits import ExploitDiscovery
    
    print("Ruby Module Discovery - Direct Execution")
    print("=" * 45)
    
    discovery = ExploitDiscovery()
    modules = discovery.discover_all_modules()
    
    print(f"\nDiscovery complete! Found {len(modules)} post-2020 modules")
    
    # Generate reports
    report_info = discovery.generate_reports()
    
    print(f"\nSummary:")
    print(f"  Total modules: {report_info['total_modules']}")
    print(f"  Need conversion: {report_info['needs_conversion']}")
    print(f"\nReports generated in /workspace/tools/dev/")
    
except Exception as e:
    print(f"Error running discovery: {e}")
    import traceback
    traceback.print_exc()