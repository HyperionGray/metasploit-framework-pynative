# Legacy Modules Directory

## Overview

This directory contains Ruby-based Metasploit modules with disclosure dates prior to 2020-01-01. These modules are maintained for backward compatibility and historical reference but are not part of the Python-native framework conversion effort.

## Purpose

As part of the Python conversion strategy (Round 4), modules are being categorized by disclosure date:

- **Post-2020 Modules**: Being converted to Python and moved to `modules/`
- **Pre-2020 Modules**: Kept in Ruby format here in `modules_legacy/`

This approach allows the project to:
1. Focus Python conversion efforts on current, actively-used exploits
2. Maintain historical modules for reference and specific use cases
3. Provide a clear migration path for legacy code

## Directory Structure

```
modules_legacy/
├── auxiliary/     # Scanner, fuzzer, and utility modules (pre-2020)
├── encoders/      # Payload encoders (pre-2020)
├── evasion/       # AV/IDS evasion modules (pre-2020)
├── exploits/      # Exploit modules (pre-2020)
│   ├── aix/
│   ├── android/
│   ├── apple_ios/
│   ├── bsd/
│   ├── dialup/
│   ├── firefox/
│   ├── freebsd/
│   ├── hpux/
│   ├── irix/
│   ├── linux/
│   ├── mainframe/
│   ├── multi/
│   ├── netware/
│   ├── osx/
│   ├── solaris/
│   ├── unix/
│   └── windows/
├── nops/          # NOP generators (pre-2020)
├── payloads/      # Payload modules (pre-2020)
└── post/          # Post-exploitation modules (pre-2020)
```

## Usage

### Running Legacy Modules

Legacy modules remain fully functional with the Ruby-based Metasploit Framework:

```bash
# Standard msfconsole usage
msfconsole

# Use a legacy module
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > set RHOSTS 192.168.1.0/24
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 > exploit
```

### Migration Status

| Category | Total Modules | Moved to Legacy | Status |
|----------|---------------|-----------------|---------|
| Exploits | ~4900 | TBD | Pending |
| Auxiliary | ~1200 | TBD | Pending |
| Post | ~400 | TBD | Pending |
| Payloads | ~600 | TBD | Pending |
| Encoders | ~45 | TBD | Pending |

## Conversion to Python

While these modules are maintained in Ruby format, high-value or frequently-used legacy modules may still be converted to Python on a case-by-case basis. To request conversion of a specific module:

1. Open an issue in the repository
2. Provide justification (usage frequency, unique functionality, etc.)
3. Tag with `legacy-conversion` label

## Module Criteria

Modules are placed in the legacy directory if they meet ANY of the following criteria:

### Primary Criterion
- **Disclosure Date**: Module's `DisclosureDate` field is before `2020-01-01`

### Secondary Criteria (may override primary)
- **Deprecated Technology**: Targets obsolete systems or software versions
- **Historical Interest**: Significant in exploit development history
- **Low Activity**: Rarely used in modern engagements
- **Platform EOL**: Targets end-of-life operating systems

### Exceptions
Some pre-2020 modules may remain in the main `modules/` directory if they:
- Target software still in widespread use
- Are frequently used in security assessments
- Have been significantly updated post-2020
- Are foundational to other modules

## Maintenance

### Stability
Legacy modules are maintained in a **frozen state**:
- ✅ Bug fixes for critical issues
- ✅ Compatibility updates for framework changes
- ❌ New features or enhancements
- ❌ Major refactoring

### Testing
Legacy modules are tested with:
- Automated syntax validation
- Basic load testing in msfconsole
- Periodic smoke tests on common targets

### Documentation
- Original module documentation preserved
- References and CVE links maintained
- Usage examples kept current
- Known issues documented

## Technical Details

### Ruby Version
Legacy modules are maintained for compatibility with:
- Ruby 2.7+
- Ruby 3.0+
- Current Metasploit Framework API

### Framework Integration
Legacy modules integrate with the framework through:
- Standard Metasploit module API
- Existing mixin architecture
- Current datastore system
- Payload generation system

### Loading Legacy Modules
The framework automatically detects and loads modules from both `modules/` and `modules_legacy/`:

```ruby
# Framework configuration (lib/msf/core/module_manager.rb)
module_paths = [
  File.join(framework_root, 'modules'),
  File.join(framework_root, 'modules_legacy')
]
```

## Migration Process

### Identifying Legacy Modules

To identify modules for migration to this directory:

```bash
# Find all modules with DisclosureDate < 2020-01-01
grep -r "DisclosureDate.*=> *['\"]20[01][0-9]" modules/exploits/ --include="*.rb"

# Count by year
for year in 2000 2001 2002 2003 2004 2005 2006 2007 2008 2009 2010 2011 2012 2013 2014 2015 2016 2017 2018 2019; do
  echo "$year: $(grep -r "DisclosureDate.*=> *['\"]$year" modules/ --include="*.rb" | wc -l)"
done
```

### Moving Modules

When moving a module to legacy:

1. **Preserve Structure**: Maintain original directory hierarchy
2. **Update References**: Check for cross-module dependencies
3. **Document Change**: Update PYTHON_TRANSLATIONS.md
4. **Test Load**: Verify module loads correctly in msfconsole

Example:
```bash
# Move exploit to legacy
mv modules/exploits/windows/smb/ms08_067_netapi.rb \
   modules_legacy/exploits/windows/smb/ms08_067_netapi.rb
```

## Contributing

### Reporting Issues
If you encounter issues with legacy modules:
1. Verify the module still loads in msfconsole
2. Check if the issue exists in the latest framework version
3. Report via GitHub issues with `legacy-module` tag

### Code Contributions
Contributions to legacy modules are accepted for:
- Critical bug fixes
- Security vulnerabilities in module code
- Compatibility with framework updates
- Documentation improvements

### Python Conversion
To contribute a Python conversion of a legacy module:
1. Convert module following PYTHON_CONVERSION_STRATEGY.md
2. Place Python version in `modules/`
3. Keep Ruby version in `modules_legacy/`
4. Update documentation
5. Submit PR with both versions

## Related Documentation

- [PYTHON_CONVERSION_STRATEGY.md](../PYTHON_CONVERSION_STRATEGY.md) - Python conversion guidelines
- [PYTHON_TRANSLATIONS.md](../PYTHON_TRANSLATIONS.md) - List of converted modules
- [PYTHON_QUICKSTART.md](../PYTHON_QUICKSTART.md) - Python module quick start
- [CONTRIBUTING.md](../CONTRIBUTING.md) - General contribution guidelines

## Statistics

### Module Count by Era

| Era | Years | Exploits | Auxiliary | Post | Total |
|-----|-------|----------|-----------|------|-------|
| Ancient | 2000-2005 | ~200 | ~50 | ~10 | ~260 |
| Classic | 2006-2010 | ~800 | ~200 | ~50 | ~1050 |
| Modern | 2011-2015 | ~1200 | ~300 | ~100 | ~1600 |
| Recent | 2016-2019 | ~1500 | ~400 | ~150 | ~2050 |
| **Legacy Total** | **2000-2019** | **~3700** | **~950** | **~310** | **~4960** |
| **Current** | **2020-2024** | **~1200** | **~250** | **~90** | **~1540** |

### Top Legacy Platforms

1. **Windows**: ~2000 modules (40%)
2. **Linux**: ~800 modules (16%)
3. **Multi-platform**: ~600 modules (12%)
4. **Unix**: ~400 modules (8%)
5. **Others**: ~1160 modules (24%)

### Frequently Used Legacy Modules

Even in legacy status, some modules remain popular:
- `exploit/windows/smb/ms17_010_eternalblue`
- `exploit/windows/smb/ms08_067_netapi`
- `exploit/multi/http/struts2_content_type_ognl`
- `exploit/unix/webapp/drupal_drupalgeddon2`
- `auxiliary/scanner/smb/smb_version`

These modules may be prioritized for Python conversion despite pre-2020 disclosure dates.

## Future Plans

### Short Term (2024-2025)
- Establish automated migration scripts
- Complete categorization of all pre-2020 modules
- Create legacy module test suite
- Document most-used legacy modules

### Long Term (2025+)
- Selective Python conversion of high-value legacy modules
- Deprecated module archival system
- Enhanced legacy module discovery
- Integration with module modernization efforts

## Contact

For questions about legacy modules:
- GitHub Discussions: Tag with `legacy-modules`
- Module Maintainers: See module author fields
- Framework Issues: GitHub issue tracker

---

**Note**: This directory is part of the ongoing Python-native conversion effort (Round 4). The presence of modules here does not indicate deprecation or removal - they remain fully functional and supported within the Ruby framework.
