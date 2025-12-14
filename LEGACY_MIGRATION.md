# Legacy Module Migration Summary

## Overview

This document summarizes the migration of legacy Metasploit Framework modules to the `modules/legacy/` directory structure.

## Migration Criteria

### Pre-2020 Modules
All modules with disclosure dates before January 1, 2020 were moved to legacy. These represent older vulnerabilities and techniques that are less relevant for modern penetration testing.

### Redundant Auxiliary Modules
The following categories of auxiliary modules were moved to legacy as they are better served by specialized tools:

- **Port Scanners** (`auxiliary/scanner/portscan/*`)
  - Tools like nmap, masscan, and rustscan provide superior performance
  - 5 modules moved

- **Network Sniffers** (`auxiliary/sniffer/*`)
  - Wireshark, tcpdump, and tshark offer better packet analysis
  - 1 module moved

- **ARP Spoofing** (`auxiliary/spoof/arp/*`)
  - Better handled by arpspoof, ettercap, bettercap
  - Modules moved

- **DNS Spoofing** (`auxiliary/spoof/dns/*`)
  - Specialized DNS tools are more effective
  - Modules moved

- **DoS Modules** (`auxiliary/dos/*`)
  - Generic denial of service tools with limited practical use
  - 48 modules moved

## Migration Statistics

### Modules Moved to Legacy
- **Total Moved**: 2,420 modules
- **Pre-2020 Exploits**: 2,011
- **Pre-2020 Auxiliary**: 340
- **Pre-2020 Post-Exploitation**: 15
- **Redundant Auxiliary**: 54

### Remaining Active Modules
- **Total Active**: 2,482 modules
- **Exploits**: 577 (542 with 2020+ dates)
- **Auxiliary**: 907 (121 with 2020+ dates)
- **Post-Exploitation**: 418 (10 with 2020+ dates)
- **Payloads**: 508
- **Encoders**: 49
- **Evasion**: 9
- **NOPs**: 14

### Year Distribution of Active Dated Modules
- **2020**: 150 modules
- **2021**: 113 modules
- **2022**: 110 modules
- **2023**: 123 modules
- **2024**: 104 modules
- **2025**: 73 modules

**Total Active Modules with 2020+ Dates**: 673

## Directory Structure

```
modules/
├── auxiliary/           # 907 active auxiliary modules
├── encoders/            # 49 encoder modules
├── evasion/             # 9 evasion modules
├── exploits/            # 577 active exploit modules
├── nops/                # 14 NOP generator modules
├── payloads/            # 508 payload modules
├── post/                # 418 active post-exploitation modules
└── legacy/              # 2,420 legacy modules
    ├── auxiliary/       # 394 legacy auxiliary modules
    ├── exploits/        # 2,011 legacy exploit modules
    └── post/            # 15 legacy post-exploitation modules
```

## Impact on Framework

### What Changed
- Legacy modules moved to `modules/legacy/` subdirectory
- Directory structure preserved within legacy
- All modules remain functional and loadable
- Module references updated to include `legacy/` prefix when needed

### What Didn't Change
- All modules remain in Ruby (as specified in requirements)
- Module loading mechanism unchanged
- Module functionality unchanged
- API and interfaces unchanged

## Using Legacy Modules

Legacy modules can still be used by referencing them with the `legacy/` prefix:

```ruby
msf6 > use legacy/exploits/windows/smb/ms08_067_netapi
msf6 > use legacy/auxiliary/scanner/portscan/tcp
```

## Rationale

### Focus on Modern Threats
By separating legacy modules, the framework becomes more focused on current and relevant security issues. The 673 modules with 2020+ disclosure dates represent actively maintained and relevant exploits.

### Reduced Maintenance Burden
Legacy modules receive best-effort support, allowing developers to focus on maintaining modern modules that target current vulnerabilities.

### Better Tool Selection
Removing redundant auxiliary modules encourages users to leverage specialized tools (nmap for scanning, Wireshark for packet analysis) that are better suited for those tasks.

### Preserved History
All legacy modules remain available for historical research, training, and scenarios where legacy systems must be tested.

## Recommendations for Users

### For Modern Penetration Testing
- Focus on modules in the main `modules/` directory
- Use specialized tools (nmap, Wireshark, etc.) for scanning and enumeration
- Prioritize modules with recent disclosure dates (2020+)

### For Legacy System Testing
- Use modules from `modules/legacy/` when targeting older systems
- Understand that legacy modules may have limited support
- Consider if the vulnerability is still relevant to your engagement

### For Development
- New modules should target current vulnerabilities (within 4-5 years)
- Avoid creating auxiliary modules that duplicate existing tools
- Follow modern Metasploit development best practices

## Future Considerations

- Legacy modules may receive security fixes and critical updates
- Periodic review of active modules to identify new legacy candidates
- Continued focus on maintaining high-quality, relevant modules in the active set
- Potential for further categorization within legacy (by decade, by risk level, etc.)

---

**Migration Date**: December 2025  
**Framework Version**: Post-Legacy-Migration
