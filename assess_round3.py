#!/usr/bin/env python3
import os
from pathlib import Path

workspace = Path("/workspace")

# Count Ruby files in key Round 3 directories
auxiliary_dir = workspace / "modules" / "auxiliary"
post_dir = workspace / "modules" / "post"
encoder_dir = workspace / "lib" / "msf" / "core" / "encoder"
payload_dir = workspace / "lib" / "msf" / "core" / "payload"

print("ROUND 3 RUBY FILE ASSESSMENT")
print("=" * 50)

# Count auxiliary modules
if auxiliary_dir.exists():
    aux_rb_files = list(auxiliary_dir.rglob("*.rb"))
    aux_py_files = list(auxiliary_dir.rglob("*.py"))
    print(f"Auxiliary modules:")
    print(f"  Ruby files (.rb): {len(aux_rb_files)}")
    print(f"  Python files (.py): {len(aux_py_files)}")
    
    # Show breakdown by subdirectory
    aux_dirs = {}
    for rb_file in aux_rb_files:
        rel_path = rb_file.relative_to(auxiliary_dir)
        dir_name = str(rel_path.parent) if rel_path.parent != Path('.') else 'root'
        aux_dirs[dir_name] = aux_dirs.get(dir_name, 0) + 1
    
    print(f"  Top auxiliary categories:")
    for dir_name, count in sorted(aux_dirs.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"    {count:3d} files in {dir_name}")

print()

# Count post-exploitation modules
if post_dir.exists():
    post_rb_files = list(post_dir.rglob("*.rb"))
    post_py_files = list(post_dir.rglob("*.py"))
    print(f"Post-exploitation modules:")
    print(f"  Ruby files (.rb): {len(post_rb_files)}")
    print(f"  Python files (.py): {len(post_py_files)}")
    
    # Show breakdown by platform
    post_dirs = {}
    for rb_file in post_rb_files:
        rel_path = rb_file.relative_to(post_dir)
        dir_name = str(rel_path.parent) if rel_path.parent != Path('.') else 'root'
        post_dirs[dir_name] = post_dirs.get(dir_name, 0) + 1
    
    print(f"  Top post-exploitation categories:")
    for dir_name, count in sorted(post_dirs.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"    {count:3d} files in {dir_name}")

print()

# Count encoder modules
if encoder_dir.exists():
    enc_rb_files = list(encoder_dir.rglob("*.rb"))
    enc_py_files = list(encoder_dir.rglob("*.py"))
    print(f"Encoder modules:")
    print(f"  Ruby files (.rb): {len(enc_rb_files)}")
    print(f"  Python files (.py): {len(enc_py_files)}")

print()

# Count payload modules
if payload_dir.exists():
    pay_rb_files = list(payload_dir.rglob("*.rb"))
    pay_py_files = list(payload_dir.rglob("*.py"))
    print(f"Payload modules:")
    print(f"  Ruby files (.rb): {len(pay_rb_files)}")
    print(f"  Python files (.py): {len(pay_py_files)}")

print()

# Total Round 3 scope
total_rb = 0
total_py = 0

if auxiliary_dir.exists():
    total_rb += len(aux_rb_files)
    total_py += len(aux_py_files)
if post_dir.exists():
    total_rb += len(post_rb_files)
    total_py += len(post_py_files)
if encoder_dir.exists():
    total_rb += len(enc_rb_files)
    total_py += len(enc_py_files)
if payload_dir.exists():
    total_rb += len(pay_rb_files)
    total_py += len(pay_py_files)

print(f"ROUND 3 TOTALS:")
print(f"  Ruby files to convert: {total_rb}")
print(f"  Python files existing: {total_py}")
print(f"  Conversion progress: {total_py}/{total_rb + total_py} ({100*total_py/(total_rb + total_py) if (total_rb + total_py) > 0 else 0:.1f}%)")

print("\n" + "=" * 50)
print("ROUND 3 RECOMMENDATION:")
if total_py < 10:  # If less than 10 Python files exist in Round 3 scope
    print("❌ Round 3 NOT COMPLETE - Need to convert auxiliary, post, encoder, and payload modules")
    print("📋 Suggested approach:")
    print("   1. Convert 2-3 representative auxiliary modules from top categories")
    print("   2. Convert 2-3 representative post-exploitation modules from top platforms")
    print("   3. Convert 1-2 encoder modules")
    print("   4. Convert 1-2 payload modules")
    print("   5. Update framework to support these module types")
else:
    print("✅ Round 3 appears to have significant progress")
    print("🔍 Review existing Python modules to confirm Round 3 completion")