#!/usr/bin/env python3

import sys
import os
from pathlib import Path
sys.path.append('/workspace/tools/dev')

from discover_post_2020_exploits import ExploitDiscovery

# Run discovery on just the HTTP exploits first to test
discovery = ExploitDiscovery()

print("Running limited discovery on Windows HTTP exploits...")
http_path = Path("/workspace/modules/exploits/windows/http")
modules = discovery.scan_directory(http_path)

print(f"Found {len(modules)} post-2020 HTTP exploits")

# Show first 10
for i, module in enumerate(modules[:10]):
    print(f"{i+1}. {module['relative_path']}")
    print(f"   Name: {module['name']}")
    print(f"   Date: {module['disclosure_date']}")
    print(f"   CVEs: {', '.join(module['cves']) if module['cves'] else 'None'}")
    print()

# Save just this subset
discovery.discovered_modules = modules
report_info = discovery.generate_reports("/workspace/tools/dev")
print(f"Generated reports for {len(modules)} HTTP modules")