#!/usr/bin/env python3
"""
Analyze the Windows API constants file to understand categorization patterns.
"""

import re
from collections import defaultdict, Counter

def analyze_constants_file(filepath):
    """Analyze the constants file and categorize by prefixes."""
    
    constants = []
    prefixes = defaultdict(list)
    
    # Read the file and extract constants
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Find all add_const calls
    pattern = r"win_const_mgr\.add_const\('([^']+)',\s*0x[0-9A-Fa-f]+\)"
    matches = re.findall(pattern, content)
    
    print(f"Found {len(matches)} constants")
    
    # Categorize by prefixes
    for const_name in matches:
        constants.append(const_name)
        
        # Extract prefix (everything before first underscore or first digit)
        if '_' in const_name:
            prefix = const_name.split('_')[0]
        else:
            # For constants without underscore, take first few chars
            prefix = const_name[:3] if len(const_name) > 3 else const_name
            
        prefixes[prefix].append(const_name)
    
    # Count prefixes
    prefix_counts = Counter({k: len(v) for k, v in prefixes.items()})
    
    print("\nTop 50 prefixes by count:")
    for prefix, count in prefix_counts.most_common(50):
        print(f"{prefix:20} : {count:5} constants")
        
    print(f"\nTotal prefixes: {len(prefix_counts)}")
    print(f"Total constants: {len(constants)}")
    
    # Look for logical groupings
    print("\n=== Suggested Logical Groupings ===")
    
    # Error codes
    error_prefixes = [p for p in prefix_counts if 'ERROR' in p or 'ERR' in p]
    error_count = sum(prefix_counts[p] for p in error_prefixes)
    print(f"Error codes ({len(error_prefixes)} prefixes): {error_count} constants")
    
    # Window messages
    wm_prefixes = [p for p in prefix_counts if p.startswith('WM') or 'MSG' in p]
    wm_count = sum(prefix_counts[p] for p in wm_prefixes)
    print(f"Window messages ({len(wm_prefixes)} prefixes): {wm_count} constants")
    
    # Registry
    reg_prefixes = [p for p in prefix_counts if 'HKEY' in p or 'REG' in p or 'KEY' in p]
    reg_count = sum(prefix_counts[p] for p in reg_prefixes)
    print(f"Registry ({len(reg_prefixes)} prefixes): {reg_count} constants")
    
    # Security/Certificates
    sec_prefixes = [p for p in prefix_counts if any(x in p for x in ['CERT', 'CRYPT', 'SEC', 'AUTH', 'TRUST'])]
    sec_count = sum(prefix_counts[p] for p in sec_prefixes)
    print(f"Security/Crypto ({len(sec_prefixes)} prefixes): {sec_count} constants")
    
    # File system
    file_prefixes = [p for p in prefix_counts if any(x in p for x in ['FILE', 'DIR', 'DRIVE', 'VOLUME', 'DISK'])]
    file_count = sum(prefix_counts[p] for p in file_prefixes)
    print(f"File system ({len(file_prefixes)} prefixes): {file_count} constants")
    
    # Network/HTTP
    net_prefixes = [p for p in prefix_counts if any(x in p for x in ['HTTP', 'NET', 'DNS', 'TCP', 'UDP', 'IP', 'SOCKET', 'WSAE'])]
    net_count = sum(prefix_counts[p] for p in net_prefixes)
    print(f"Network ({len(net_prefixes)} prefixes): {net_count} constants")
    
    # Database/SQL
    db_prefixes = [p for p in prefix_counts if 'SQL' in p or 'DB' in p]
    db_count = sum(prefix_counts[p] for p in db_prefixes)
    print(f"Database ({len(db_prefixes)} prefixes): {db_count} constants")
    
    # Graphics/DirectX
    gfx_prefixes = [p for p in prefix_counts if any(x in p for x in ['DD', 'D3D', 'GDI', 'DIB', 'BMP', 'IMAGE'])]
    gfx_count = sum(prefix_counts[p] for p in gfx_prefixes)
    print(f"Graphics ({len(gfx_prefixes)} prefixes): {gfx_count} constants")
    
    return prefixes, prefix_counts

if __name__ == "__main__":
    filepath = "/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb"
    analyze_constants_file(filepath)