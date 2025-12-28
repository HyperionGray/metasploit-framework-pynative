#!/usr/bin/env python3

import re
from collections import defaultdict, Counter

# Read the api_constants.rb file
file_path = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb'
with open(file_path, 'r') as f:
    content = f.read()

# Extract all constants
constants = re.findall(r"win_const_mgr\.add_const\('([^']+)',", content)

print(f"Total constants found: {len(constants)}")

# Analyze prefixes
prefix_counts = Counter()
for const in constants:
    # Extract prefix (up to first underscore)
    if '_' in const:
        prefix = const.split('_')[0]
    else:
        prefix = const[:4]
    prefix_counts[prefix] += 1

# Sort by count and show top prefixes
print("\nTop 50 prefixes by count:")
for prefix, count in prefix_counts.most_common(50):
    print(f"{prefix}: {count}")

# Analyze common categories
categories = {
    'ERROR': [c for c in constants if c.startswith('ERROR_')],
    'WM': [c for c in constants if c.startswith('WM_')],
    'VK': [c for c in constants if c.startswith('VK_')],
    'LANG': [c for c in constants if c.startswith('LANG_')],
    'SUBLANG': [c for c in constants if c.startswith('SUBLANG_')],
    'DNS': [c for c in constants if c.startswith('DNS_')],
    'SQL': [c for c in constants if c.startswith('SQL_')],
    'RPC': [c for c in constants if c.startswith('RPC_')],
    'INTERNET': [c for c in constants if c.startswith('INTERNET_')],
    'WINHTTP': [c for c in constants if c.startswith('WINHTTP_')],
    'CERT': [c for c in constants if c.startswith('CERT_')],
    'CRYPT': [c for c in constants if c.startswith('CRYPT')],
    'SECURITY': [c for c in constants if c.startswith('SECURITY_')],
    'SERVICE': [c for c in constants if c.startswith('SERVICE_')],
    'FILE': [c for c in constants if c.startswith('FILE_')],
    'REG': [c for c in constants if c.startswith('REG')],
    'KEY': [c for c in constants if c.startswith('KEY_')],
    'GENERIC': [c for c in constants if c.startswith('GENERIC_')],
    'STANDARD': [c for c in constants if c.startswith('STANDARD_')],
    'PROCESS': [c for c in constants if c.startswith('PROCESS_')],
    'THREAD': [c for c in constants if c.startswith('THREAD_')],
    'TOKEN': [c for c in constants if c.startswith('TOKEN_')],
    'IMAGE': [c for c in constants if c.startswith('IMAGE_')],
    'DEBUG': [c for c in constants if c.startswith('DEBUG_')],
    'EXCEPTION': [c for c in constants if c.startswith('EXCEPTION_')],
    'HKEY': [c for c in constants if c.startswith('HKEY_')],
    'HWND': [c for c in constants if c.startswith('HWND_')],
    'HANDLE': [c for c in constants if c.startswith('HANDLE_')],
    'DEVICE': [c for c in constants if c.startswith('DEVICE_')],
    'DRIVER': [c for c in constants if c.startswith('DRIVER_')],
    'PRINTER': [c for c in constants if c.startswith('PRINTER_')],
    'FONT': [c for c in constants if c.startswith('FONT_')],
    'COLOR': [c for c in constants if c.startswith('COLOR_')],
    'BRUSH': [c for c in constants if c.startswith('BRUSH_')],
    'PEN': [c for c in constants if c.startswith('PEN_')],
    'BITMAP': [c for c in constants if c.startswith('BITMAP_')],
    'ICON': [c for c in constants if c.startswith('ICON_')],
    'CURSOR': [c for c in constants if c.startswith('CURSOR_')],
    'MENU': [c for c in constants if c.startswith('MENU_')],
    'DIALOG': [c for c in constants if c.startswith('DIALOG_')],
    'WINDOW': [c for c in constants if c.startswith('WINDOW_')],
    'CONTROL': [c for c in constants if c.startswith('CONTROL_')],
    'BUTTON': [c for c in constants if c.startswith('BUTTON_')],
    'EDIT': [c for c in constants if c.startswith('EDIT_')],
    'LISTBOX': [c for c in constants if c.startswith('LISTBOX_')],
    'COMBOBOX': [c for c in constants if c.startswith('COMBOBOX_')],
    'SCROLLBAR': [c for c in constants if c.startswith('SCROLLBAR_')],
    'STATIC': [c for c in constants if c.startswith('STATIC_')],
    'NETWORK': [c for c in constants if c.startswith('NETWORK_')],
    'SOCKET': [c for c in constants if c.startswith('SOCKET_')],
    'TCP': [c for c in constants if c.startswith('TCP_')],
    'UDP': [c for c in constants if c.startswith('UDP_')],
    'IP': [c for c in constants if c.startswith('IP_')],
    'HTTP': [c for c in constants if c.startswith('HTTP_')],
    'FTP': [c for c in constants if c.startswith('FTP_')],
    'SMTP': [c for c in constants if c.startswith('SMTP_')],
}

print("\nCategory analysis:")
total_categorized = 0
for category, consts in categories.items():
    if len(consts) > 0:
        print(f"{category}: {len(consts)} constants")
        total_categorized += len(consts)

# Find uncategorized constants
categorized_set = set()
for consts in categories.values():
    categorized_set.update(consts)

uncategorized = [c for c in constants if c not in categorized_set]

print(f"\nTotal categorized: {total_categorized}")
print(f"Uncategorized constants: {len(uncategorized)}")
print("Sample uncategorized (first 30):")
for c in uncategorized[:30]:
    print(f"  {c}")

# Group uncategorized by prefix for better understanding
uncategorized_prefixes = Counter()
for const in uncategorized:
    if '_' in const:
        prefix = const.split('_')[0]
    else:
        prefix = const[:4]
    uncategorized_prefixes[prefix] += 1

print(f"\nTop uncategorized prefixes:")
for prefix, count in uncategorized_prefixes.most_common(20):
    print(f"{prefix}: {count}")