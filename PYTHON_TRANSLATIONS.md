# Ruby to Python Translation Summary

This document summarizes the Ruby files that have been translated to Python in this repository.

## Recent Exploit Module Conversions (2024)

### 55. modules/exploits/linux/http/apache_hugegraph_gremlin_rce.rb → modules/exploits/linux/http/apache_hugegraph_gremlin_rce.py
**Purpose:** Apache HugeGraph Gremlin RCE (CVE-2024-27348)

**Key Features:**
- Remote Code Execution in Apache HugeGraph Server versions before 1.3.0
- Gremlin sandbox bypass vulnerability
- Java reflection-based command execution
- Automatic version detection and vulnerability checking

**Usage:**
```bash
python3 modules/exploits/linux/http/apache_hugegraph_gremlin_rce.py --host 192.168.1.100 --port 8080
python3 modules/exploits/linux/http/apache_hugegraph_gremlin_rce.py --host target.example.com --check-only
```

### 56. modules/exploits/example_webapp.rb → modules/exploits/example_webapp.py
**Purpose:** Sample web application exploit demonstrating common patterns

**Key Features:**
- Educational example showing exploit development techniques
- Version detection and vulnerability checking
- Multiple authentication methods (Basic Auth and form-based)
- Command injection through POST parameters
- File upload via multipart form-data
- Comprehensive error handling

**Usage:**
```bash
python3 modules/exploits/example_webapp.py --host 192.168.1.100 --username admin --password pass123
python3 modules/exploits/example_webapp.py --host target.example.com --check-only --verbose
```

## Translated Files

### 1. lib/rex/proto/smb/utils.rb → lib/rex/proto/smb/utils.py
**Purpose:** SMB protocol utility functions

**Key Features:**
- Access mode conversion for SMB file operations
- File mode mask generation
- SMB time ↔ Unix timestamp conversion
- NetBIOS name encoding/decoding

**Usage Example:**
```python
from lib.rex.proto.smb.utils import Utils

# NetBIOS encoding
encoded = Utils.nbname_encode('WORKGROUP')
print(encoded)  # FHEPFCELEHFCEPFFFACACACACACACACA

# Time conversion
import time
unix_time = int(time.time())
hi, lo = Utils.time_unix_to_smb(unix_time)
back = Utils.time_smb_to_unix(hi, lo)
```

### 2. tools/modules/module_rank.rb → tools/modules/module_rank.py
**Purpose:** Display module rank information for Metasploit modules

**Key Features:**
- Filter modules by rank (Manual, Low, Average, Normal, Good, Great, Excellent)
- Sort by rank or module type
- Filter by module type (exploit, payload, post, nop, encoder, auxiliary)

**Usage:**
```bash
python3 tools/modules/module_rank.py --help
python3 tools/modules/module_rank.py -m Normal -M Excellent -s
```

### 3. tools/modules/module_count.rb → tools/modules/module_count.py
**Purpose:** Count modules by type and output as CSV

**Key Features:**
- Count exploit, auxiliary, post, payload, encoder, and nop modules
- CSV output format

### 4. tools/modules/module_mixins.rb → tools/modules/module_mixins.py
**Purpose:** List all modules with their mixins (using Python's MRO)

**Key Features:**
- Identify module inheritance patterns
- Sort and count mixin usage across modules

### 5. tools/modules/solo.rb → tools/modules/solo.py
**Purpose:** Run a module outside of Metasploit Framework

**Key Features:**
- Message logging with different levels (error, warning, good, info)
- Report processing
- Module execution outside framework context

### 6. modules/encoders/ruby/base64.rb → modules/encoders/ruby/ruby_base64_encoder.py
**Purpose:** Ruby Base64 encoder for payloads

**Key Features:**
- Base64 encoding with Ruby eval wrapper
- Badchar checking
- Generates: `eval(%(base64_string).unpack(%(m0)).first)`

**Usage:**
```bash
python3 modules/encoders/ruby/ruby_base64_encoder.py 'puts "hello"'
# Output: eval(%(cHV0cyAiaGVsbG8i).unpack(%(m0)).first)
```

### 7. scripts/meterpreter/get_local_subnets.rb → scripts/meterpreter/get_local_subnets.py
**Purpose:** Meterpreter script to display local subnets

**Key Features:**
- List local subnets based on host routes
- Filter out multicast and loopback interfaces

### 8. external/source/unixasm/objdumptoc.rb → external/source/unixasm/objdumptoc.py
**Purpose:** Convert objdump output to C array format

**Key Features:**
- Parse objdump assembly output
- Generate C-style byte arrays
- Include assembly comments in output

**Usage:**
```bash
objdump -dM suffix <file> | python3 external/source/unixasm/objdumptoc.py
```

### 9. external/source/unixasm/aix-power.rb → external/source/unixasm/aix-power.py
**Purpose:** Generate AIX PowerPC assembly with system call numbers

**Key Features:**
- Support for multiple AIX versions (5.3.7-6.1.4)
- Generate system call sequences for socket operations
- Template-based code generation

### 10. lib/msf/core/modules/external.rb → lib/msf/core/modules/external.py
**Purpose:** Support for loading external Metasploit modules

**Key Features:**
- Module path management
- Framework integration
- Lazy metadata loading
- Module execution with callbacks

### 11. scripts/meterpreter/winenum.rb → scripts/meterpreter/winenum.py
**Purpose:** Comprehensive Windows local enumeration script

**Key Features:**
- Gathers system, network, and user information
- Dumps password hashes
- Lists security tokens
- Detects virtual machine environments
- Optional process migration, registry dumping, and event log clearing

**Usage:**
```bash
python3 scripts/meterpreter/winenum.py --help
```


### 12. lib/msf/util/helper.rb → lib/msf/util/helper.py
**Purpose:** Cross-platform utility functions

**Key Features:**
- `which()` function to find executables in PATH
- Cross-platform compatibility (Windows/Unix)
- Handles PATHEXT on Windows

**Usage:**
```python
from lib.msf.util.helper import Helper

# Find python3 executable
python_path = Helper.which('python3')
print(python_path)  # /usr/bin/python3
```

### 13. lib/msf/util/ruby_deserialization.rb → lib/msf/util/ruby_deserialization.py
**Purpose:** Ruby deserialization exploit payloads

**Key Features:**
- Generate payloads for Ruby deserialization vulnerabilities
- Supports `net_writeadapter` payload (universal gadget for Ruby 2.x-3.x)
- Marshal format payload generation

**Usage:**
```python
from lib.msf.util.ruby_deserialization import RubyDeserialization

# Generate payload
payload = RubyDeserialization.payload('net_writeadapter', 'whoami')
# Returns bytes of serialized Ruby Marshal payload
```

### 14. lib/msf/util/python_deserialization.rb → lib/msf/util/python_deserialization.py
**Purpose:** Python deserialization exploit payloads

**Key Features:**
- Generate payloads for Python deserialization vulnerabilities (pickle)
- Supports `py3_exec` (direct execution) and `py3_exec_threaded` (threaded execution)
- Automatic escaping of special characters

**Usage:**
```python
from lib.msf.util.python_deserialization import PythonDeserialization

# Generate payload for Python 3.x
payload = PythonDeserialization.payload('py3_exec', 'import os; os.system("id")')
# Returns pickle protocol string
```

### 15. lib/msf/util/java_deserialization.rb → lib/msf/util/java_deserialization.py
**Purpose:** Java deserialization exploit payloads (ysoserial)

**Key Features:**
- Load and generate ysoserial payloads
- Support for multiple payload types (CommonsCollections1-7, BeanShell1, etc.)
- Dynamic command injection with automatic length correction
- Evasion through randomization of ysoserial signatures

**Usage:**
```python
from lib.msf.util.java_deserialization import JavaDeserialization

# List available payloads
payloads = JavaDeserialization.ysoserial_payload_names()

# Generate payload
payload = JavaDeserialization.ysoserial_payload('CommonsCollections1', 'calc.exe')
# Returns bytes of serialized Java object
```

### 16. tools/dev/set_binary_encoding.rb → tools/dev/set_binary_encoding.py
**Purpose:** Add UTF-8 encoding declarations to Python files

**Key Features:**
- Automatically adds `# -*- coding: utf-8 -*-` to Python files
- Handles files with or without shebang lines
- Skips files that already have encoding declarations

**Usage:**
```bash
python3 tools/dev/set_binary_encoding.py myfile.py
```

### 17. scripts/meterpreter/migrate.rb → scripts/meterpreter/migrate.py
**Purpose:** Meterpreter process migration script

**Key Features:**
- Migrate to specific PID or process name
- Option to spawn new process (notepad.exe) for migration
- Kill original process after migration
- Windows platform support

**Usage:**
```bash
python3 scripts/meterpreter/migrate.py -p 1234
python3 scripts/meterpreter/migrate.py -n explorer.exe
python3 scripts/meterpreter/migrate.py -f -k
```

### 18. scripts/meterpreter/uploadexec.rb → scripts/meterpreter/uploadexec.py
**Purpose:** Upload and execute files on target system

**Key Features:**
- Upload files to target (default: %TEMP%)
- Execute with optional arguments
- Verbose mode to capture output
- Optional file removal after execution
- Optional session termination

**Usage:**
```bash
python3 scripts/meterpreter/uploadexec.py -e payload.exe
python3 scripts/meterpreter/uploadexec.py -e script.bat -p C:\\temp -v -r
```

### 19. scripts/shell/migrate.rb → scripts/shell/migrate.py
**Purpose:** Display message that migration is not supported for CommandShell sessions

**Key Features:**
- Simple error message for command shell sessions

**Usage:**
```bash
python3 scripts/shell/migrate.py
# Output: [-] Error: command shell sessions do not support migration
```

### 20. scripts/meterpreter/get_application_list.rb → scripts/meterpreter/get_application_list.py
**Purpose:** List installed applications and their versions

**Key Features:**
- Enumerate installed applications from Windows registry
- Query both HKLM and HKCU Uninstall keys
- Multi-threaded registry queries for performance
- Formatted table output

**Usage:**
```bash
python3 scripts/meterpreter/get_application_list.py
```

### 21. scripts/meterpreter/file_collector.rb → scripts/meterpreter/file_collector.py
**Purpose:** Search and collect files matching specific patterns

**Key Features:**
- Search for files by pattern/wildcard
- Support for multiple search patterns (pipe-separated)
- Recursive directory search
- Save search results to file
- Download files from results list

**Usage:**
```bash
# Search for files
python3 scripts/meterpreter/file_collector.py -d C:\\Users -f "*.doc|*.pdf" -r -o results.txt

# Download files from list
python3 scripts/meterpreter/file_collector.py -i results.txt -l ./downloads
```

### 22. scripts/meterpreter/virtualbox_sysenter_dos.rb → scripts/meterpreter/virtualbox_sysenter_dos.py
**Purpose:** Trigger VirtualBox DoS vulnerability (CVE-2008-3691)

**Key Features:**
- Spawns calculator process
- Allocates memory and writes shellcode
- Creates thread to execute SYSENTER instruction
- Causes VirtualBox guest to crash

### 23. scripts/meterpreter/powerdump.rb → scripts/meterpreter/powerdump.py
**Purpose:** Extract username/password hashes using PowerShell

**Key Features:**
- Uses PowerShell to dump SAM database
- Works on Windows 7 and Server 2008+
- Sets execution policy temporarily
- Cleans up files after execution

### 24. scripts/meterpreter/multiscript.rb → scripts/meterpreter/multiscript.py
**Purpose:** Run multiple Meterpreter scripts sequentially

**Key Features:**
- Execute list of scripts from command line
- Read script list from file
- Continue on errors
- Comment support (#)

### 25. scripts/meterpreter/multi_console_command.rb → scripts/meterpreter/multi_console_command.py
**Purpose:** Run multiple console commands on Meterpreter session

**Key Features:**
- Execute commands from command line (comma-separated)
- Read commands from file
- Silent mode (background execution)

### 26. scripts/meterpreter/screen_unlock.rb → scripts/meterpreter/screen_unlock.py
**Purpose:** Unlock Windows screen by patching msv1_0.dll

**Key Features:**
- Patches lsass.exe memory to bypass authentication
- Supports Windows XP SP2/SP3, Vista, and 7
- Can revert patch to re-enable locking
- Requires system privileges

### 27. scripts/meterpreter/search_dwld.rb → scripts/meterpreter/search_dwld.py
**Purpose:** Recursively search and download files matching patterns

**Key Features:**
- Predefined filters (office, win9x, passwd)
- Custom pattern support
- Recursive directory scanning
- Downloads to temp directory

### 28. scripts/meterpreter/hostsedit.rb → scripts/meterpreter/hostsedit.py
**Purpose:** Modify Windows hosts file for DNS redirection

**Key Features:**
- Add single or multiple host entries
- Backup hosts file before modification
- Clear DNS cache after changes
- UAC detection for Vista/7

### 29. scripts/meterpreter/multicommand.rb → scripts/meterpreter/multicommand.py
**Purpose:** Execute multiple Windows commands with output capture

**Key Features:**
- Execute commands from command line or file
- Capture and display command output
- Optional output file
- Response timeout configuration

### 30. tools/dev/add_pr_fetch.rb → tools/dev/add_pr_fetch.py
**Purpose:** Add pull request fetch configuration to git config

**Key Features:**
- Automatically add PR fetch refs to .git/config
- Support for multiple remotes
- Prevents duplicates

### 31. external/source/osx/x86/src/test/write_size_and_data.rb → external/source/osx/x86/src/test/write_size_and_data.py
**Purpose:** Write data with 4-byte size prefix (little-endian)

### 32. external/source/exploits/cve-2010-4452/get_offsets.rb → external/source/exploits/cve-2010-4452/get_offsets.py
**Purpose:** Extract config and applet offsets from compiled exploit

### 33. external/source/DLLHijackAuditKit/regenerate_binaries.rb → external/source/DLLHijackAuditKit/regenerate_binaries.py
**Purpose:** Regenerate test binaries using msfvenom

**Key Features:**
- Generate EXE and DLL payloads
- Uses calc.exe and test payloads

### 34. external/source/exploits/CVE-2018-4404/gen_offsets.rb → external/source/exploits/CVE-2018-4404/gen_offsets.py
**Purpose:** Generate macOS library offsets for CVE-2018-4404 exploit

**Key Features:**
- Uses radare2 to extract function offsets
- Analyzes libdyld.dylib and libsystem_c.dylib
- Generates offsets for dyld_stub_binder, dlopen, confstr, strlen

### 35. external/source/metsvc/test.rb → external/source/metsvc/test.py
**Purpose:** Test Meterpreter connection (placeholder implementation)

### 36. external/source/exploits/CVE-2016-4655/create_bin.rb → external/source/exploits/CVE-2016-4655/create_bin.py
**Purpose:** Create flat binary from Mach-O file

**Key Features:**
- Parse Mach-O segments and sections
- Extract code and data
- Generate flat binary for exploit

### 37. external/source/exploits/CVE-2017-13861/create_bin.rb → external/source/exploits/CVE-2017-13861/create_bin.py
**Purpose:** Create exploit binary from Mach-O with payload dylib

**Key Features:**
- Parse Mach-O structure
- Generate ARM branch instruction
- Embed payload dylib at fixed offset

### 38. external/source/cmdstager/debug_asm/fix_up.rb → external/source/cmdstager/debug_asm/fix_up.py
**Purpose:** Fix up assembly based on debug.exe transcript

**Key Features:**
- Extract label addresses from debug transcript
- Replace call/jmp references
- Fix read/write handle/filename references

### 39. tools/modules/committer_count.rb → tools/modules/committer_count.py
**Purpose:** Display git commit statistics by author over a given period

**Key Features:**
- Count commits per author since a specific date
- Support flexible date formats (1y, 6m, 12w, 100d, YYYY-MM-DD)
- Sort by commit count descending

**Usage:**
```bash
python3 tools/modules/committer_count.py 2011-01-01 | head -10  # Since a particular date
python3 tools/modules/committer_count.py 1y   | head -10        # Last year
python3 tools/modules/committer_count.py 6m   | head -10        # Last six months
python3 tools/modules/committer_count.py 12w  | head -10        # Last twelve weeks
```

### 40. tools/modules/module_author.rb → tools/modules/module_author.py
**Purpose:** List modules by author and count modules per author

**Key Features:**
- Display all modules with their authors
- Count and display modules per author
- Filter by module type
- Regex matching against author field
- Sort by author or reverse sort

**Usage:**
```bash
python3 tools/modules/module_author.py --help
python3 tools/modules/module_author.py -f Exploit -s
python3 tools/modules/module_author.py -x "hdm" -r
```

### 41. tools/modules/module_commits.rb → tools/modules/module_commits.py
**Purpose:** Check commit history of modules and sort by commit count

**Key Features:**
- Analyze git commit history for module files
- Show commits per author for each module
- Sort modules by total commit count
- Works with both individual files and directories

**Usage:**
```bash
python3 tools/modules/module_commits.py modules/exploits
python3 tools/modules/module_commits.py modules/exploits/windows/smb/ms17_010_eternalblue.rb
```

### 42. tools/modules/module_description.rb → tools/modules/module_description.py
**Purpose:** List modules with their descriptions

**Key Features:**
- Display all modules with descriptions
- Filter by module type
- Framework integration placeholder

**Usage:**
```bash
python3 tools/modules/module_description.py --help
python3 tools/modules/module_description.py -f Exploit
```

### 43. tools/modules/module_license.rb → tools/modules/module_license.py
**Purpose:** List modules by licensing terms

**Key Features:**
- Display module licenses (MSF, GPL, BSD, ART, UNK)
- Filter by module type
- Sort by license or module type
- Regex matching against license field

**Usage:**
```bash
python3 tools/modules/module_license.py --help
python3 tools/modules/module_license.py -s -f Exploit
python3 tools/modules/module_license.py -x "MSF"
```

### 44. tools/modules/module_payloads.rb → tools/modules/module_payloads.py
**Purpose:** List exploit modules by compatible payloads

**Key Features:**
- Show compatible payloads for each exploit
- Framework integration placeholder

**Usage:**
```bash
python3 tools/modules/module_payloads.py
```

### 45. tools/modules/module_ports.rb → tools/modules/module_ports.py
**Purpose:** List modules by default ports they use

**Key Features:**
- Extract RPORT datastore values
- List autofilter_ports
- Sort by port number
- Framework integration placeholder

**Usage:**
```bash
python3 tools/modules/module_ports.py
```

### 46. tools/modules/module_targets.rb → tools/modules/module_targets.py
**Purpose:** List all modules with their targets

**Key Features:**
- Display module targets
- Sort by target name
- Regex filter for target matching
- Framework integration placeholder

**Usage:**
```bash
python3 tools/modules/module_targets.py --help
python3 tools/modules/module_targets.py -s
python3 tools/modules/module_targets.py -x "Windows"
```

### 47. tools/modules/payload_lengths.rb → tools/modules/payload_lengths.py
**Purpose:** List payload modules with their lengths

**Key Features:**
- Display payload sizes (no encoding or BadChar handling)
- Support for command-line datastore options
- Architecture and platform filtering
- Framework integration placeholder

**Usage:**
```bash
python3 tools/modules/payload_lengths.py
python3 tools/modules/payload_lengths.py ARCH=x64 PLATFORM=windows
```

### 48. tools/modules/module_disclodate.rb → tools/modules/module_disclodate.py
**Purpose:** List modules by disclosure date

**Key Features:**
- Display modules with disclosure dates
- Filter by date range (start and end dates)
- Filter by module type
- Exclude modules with no disclosure date
- Sort by disclosure date
- Regex matching against module names

**Usage:**
```bash
python3 tools/modules/module_disclodate.py --help
python3 tools/modules/module_disclodate.py -s -d 2020-01-01 -D 2023-12-31
python3 tools/modules/module_disclodate.py -n -f Exploit
```

### 49. lib/rex/text.rb → lib/rex/text.py
**Purpose:** Text manipulation utilities for Metasploit

**Key Features:**
- `pattern_create()` - Create cyclic patterns for exploit development
- `pattern_offset()` - Find offset of substring/integer in pattern
- `decode_base64()` - Base64 decoding
- `to_ascii()` - Convert bytes to ASCII string

**Usage:**
```python
from rex.text import Text

# Create a 100-byte pattern
pattern = Text.pattern_create(100)

# Find offset of a specific value
offset = Text.pattern_offset(pattern, "Aa3A")
print(f"Offset: {offset}")
```

### 50. tools/exploit/pattern_create.rb → tools/exploit/pattern_create.py
**Purpose:** Create cyclic patterns for buffer overflow exploitation

**Key Features:**
- Generate patterns of specified length
- Support for custom character sets
- Used to identify buffer overflow offsets

**Usage:**
```bash
python3 tools/exploit/pattern_create.py -l 200
python3 tools/exploit/pattern_create.py -l 50 -s ABC,def,123
```

### 51. tools/exploit/pattern_offset.rb → tools/exploit/pattern_offset.py
**Purpose:** Find offset of a pattern value

**Key Features:**
- Locate exact matches in patterns
- Support for hex values and 4-byte strings
- Find approximate matches with byte adjustments
- Essential for exploit development

**Usage:**
```bash
python3 tools/exploit/pattern_offset.py -q Aa3A
python3 tools/exploit/pattern_offset.py -q 41304141 -l 8192
python3 tools/exploit/pattern_offset.py -q AAAA -s ABC,def,123
```

### 52. tools/password/cpassword_decrypt.rb → tools/password/cpassword_decrypt.py
**Purpose:** Decrypt Group Policy Preferences (GPP) cpassword strings

**Key Features:**
- Decrypt cpassword values using Microsoft's public AES key
- Useful for extracting passwords from groups.xml and scheduledtasks.xml
- Handles UTF-16LE encoding and PKCS7 padding

**Usage:**
```bash
python3 tools/password/cpassword_decrypt.py AzVJmXh/J9KrU5n0czX1uBPLSUjzFE8j7dOltPD8tLk
# Output: [+] The decrypted AES password is: testpassword
```

**Dependencies:**
- pycryptodome (install with: `pip install pycryptodome`)

### 53. scripts/meterpreter/hashdump.rb → scripts/meterpreter/hashdump.py
**Purpose:** Dump Windows password hashes via Meterpreter

**Key Features:**
- Extract SAM database password hashes
- Boot key and hboot key calculation
- Password hint extraction
- Framework placeholder for meterpreter integration

**Usage:**
```bash
# Within Meterpreter session:
python3 scripts/meterpreter/hashdump.py
python3 scripts/meterpreter/hashdump.py -p 445

# Note: Standalone mode shows usage information
```

**Note:** This is a reference implementation. Actual hash dumping requires a live Meterpreter session.

### 54. scripts/meterpreter/scraper.rb → scripts/meterpreter/scraper.py
**Purpose:** Comprehensive system information gathering

**Key Features:**
- Network configuration and routing
- System information (OS, computer name)
- User and group enumeration
- Share and service enumeration
- Password hash dumping
- Registry hive export (HKLM, HKCU, HKCC, HKCR, HKU)

**Usage:**
```bash
# Within Meterpreter session:
python3 scripts/meterpreter/scraper.py

# Output stored in: logs/scripts/scraper/<host>_<timestamp>
```

**Note:** This is a reference implementation. Actual scraping requires a live Meterpreter session.

## Common Patterns

1. **Module Structure**: Ruby modules are translated to Python classes or module-level functions
2. **String Encoding**: Ruby's `pack`/`unpack` is replaced with Python's `struct` module
3. **Regular Expressions**: Ruby regex patterns work mostly as-is in Python with `re` module
4. **File I/O**: Ruby's `File.new` becomes Python's `open()` or `with open()` context manager
5. **Command Line Arguments**: Ruby's `Rex::Parser::Arguments` becomes Python's `argparse`

### Key Differences

- **Naming**: Some files renamed to avoid conflicts (e.g., base64.py → ruby_base64_encoder.py)
- **Framework Integration**: Python versions include placeholders for framework initialization as the full framework may not be implemented yet
- **String Interpolation**: Ruby's `#{var}` becomes Python's f-strings `{var}`
- **Symbols**: Ruby symbols (`:symbol`) become Python strings (`'symbol'`)
- **Class Variables**: Ruby's `@var` becomes Python's `self._var`

## Testing

All translated files have been verified for:
- ✅ Valid Python syntax (using `python3 -m py_compile`)
- ✅ Executable permissions set
- ✅ Basic functionality tests where applicable

## Future Work

These translations provide a foundation for a Python-native Metasploit implementation. Some files contain placeholders for framework integration that would need to be completed when the full Python framework is available.
