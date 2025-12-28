#!/usr/bin/env python3
"""
Quick test of the constant extraction.
"""

import re
from collections import defaultdict

def categorize_constant(const_name):
    """Categorize a constant based on its name."""
    name_upper = const_name.upper()
    
    # Error codes
    if any(x in name_upper for x in ['ERROR_', 'WSAE', '_ERR', 'FAILED', 'INVALID']):
        return 'errors'
    
    # Window messages and UI
    if any(x in name_upper for x in ['WM_', 'WS_', 'SW_', 'SWP_', 'HWND_', 'MSG_', 'WINDOW', 'DIALOG', 'MENU', 'BUTTON', 'SCROLL']):
        return 'windows'
    
    # Registry
    if any(x in name_upper for x in ['HKEY_', 'REG_', 'KEY_', 'REGISTRY']):
        return 'registry'
    
    # Security and cryptography
    if any(x in name_upper for x in ['CERT_', 'CRYPT_', 'SEC_', 'AUTH_', 'TRUST_', 'SECURITY_', 'PRIVILEGE_', 'TOKEN_', 'ACL_', 'SID_']):
        return 'security'
    
    # File system
    if any(x in name_upper for x in ['FILE_', 'DRIVE_', 'VOLUME_', 'DISK_', 'DIRECTORY_', 'FOLDER_', 'PATH_', 'GENERIC_READ', 'GENERIC_WRITE']):
        return 'filesystem'
    
    # Network
    if any(x in name_upper for x in ['HTTP_', 'DNS_', 'TCP_', 'UDP_', 'IP_', 'SOCKET_', 'NET_', 'INTERNET_', 'WINHTTP_', 'FTP_', 'SMTP_']):
        return 'network'
    
    # Database
    if any(x in name_upper for x in ['SQL_', 'DB_', 'DATABASE_', 'ODBC_']):
        return 'database'
    
    # Graphics and DirectX
    if any(x in name_upper for x in ['DD', 'D3D', 'GDI_', 'DIB_', 'BMP_', 'IMAGE_', 'BITMAP_', 'COLOR_', 'BRUSH_', 'PEN_', 'FONT_']):
        return 'graphics'
    
    # System and hardware
    if any(x in name_upper for x in ['PROCESSOR_', 'DEVICE_', 'HARDWARE_', 'SYSTEM_', 'MACHINE_', 'PLATFORM_', 'ARCH_']):
        return 'system'
    
    # Process and thread
    if any(x in name_upper for x in ['JOB_', 'THREAD_', 'PROCESS_', 'HANDLE_', 'WAIT_', 'SYNCHRONIZE']):
        return 'process'
    
    # Default to miscellaneous
    return 'miscellaneous'

def quick_test():
    """Quick test of extraction."""
    
    filepath = "/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb"
    constants = []
    categories = defaultdict(int)
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if line_num > 1000:  # Test first 1000 lines
                break
            line = line.strip()
            # Look for add_const lines
            if 'win_const_mgr.add_const(' in line:
                # Extract constant name and value using regex
                match = re.search(r"win_const_mgr\.add_const\('([^']+)',\s*(0x[0-9A-Fa-f]+)\)", line)
                if match:
                    const_name = match.group(1)
                    const_value = match.group(2)
                    category = categorize_constant(const_name)
                    constants.append((const_name, const_value, category))
                    categories[category] += 1
                else:
                    print(f"Warning: Could not parse line {line_num}: {line}")
    
    print(f"Extracted {len(constants)} constants from first 1000 lines")
    print("\nCategories found:")
    for category, count in sorted(categories.items()):
        print(f"  {category}: {count}")
    
    print("\nSample constants:")
    for const_name, const_value, category in constants[:10]:
        print(f"  {const_name} = {const_value} ({category})")

if __name__ == "__main__":
    quick_test()