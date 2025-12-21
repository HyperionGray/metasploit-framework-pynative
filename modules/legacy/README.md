# Legacy Modules

This directory contains legacy Metasploit Framework modules that have been moved here for archival purposes.

## Why Legacy?

Modules are moved to this legacy directory when they meet one or more of the following criteria:

### 1. Pre-2020 Disclosure Dates
Modules with disclosure dates before January 1, 2020 are considered legacy. These modules target older vulnerabilities that are less relevant in modern penetration testing scenarios.

### 2. Redundant Auxiliary Modules
Certain auxiliary modules have been superseded by better, more specialized tools:

- **Port Scanners** (`scanner/portscan/*`): Tools like `nmap`, `masscan`, and `rustscan` are far more efficient and feature-rich
- **Network Discovery** (`scanner/discovery/*`): Better handled by dedicated network mapping tools
- **Sniffers** (`sniffer/*`): Wireshark, tcpdump, and tshark provide superior packet analysis capabilities
- **ARP/DNS Spoofing** (`spoof/arp/*`, `spoof/dns/*`): Tools like `arpspoof`, `ettercap`, and `bettercap` are more effective
- **Basic DoS Tools** (`dos/*`): Generic denial of service modules that other tools handle better

## Statistics

- **Total Legacy Modules**: 2,420
- **Pre-2020 Exploits**: 2,011
- **Pre-2020 Auxiliary**: 340
- **Pre-2020 Post-Exploitation**: 15
- **Redundant Auxiliary**: 54

## Structure

Legacy modules maintain the same directory structure as active modules:

```
legacy/
├── auxiliary/     # Legacy auxiliary modules
├── exploits/      # Legacy exploit modules
└── post/          # Legacy post-exploitation modules
```

## Usage

Legacy modules are still fully functional and can be used if needed. They remain in Ruby and are loaded by the Metasploit Framework alongside active modules.

To use a legacy module, simply reference it with the `legacy/` prefix:

```
msf6 > use legacy/exploits/windows/smb/ms08_067_netapi
```

## Modern Alternatives

For penetration testing on modern systems, focus on:

- Modules with 2020+ disclosure dates (in the main `modules/` directory)
- Specialized security tools for scanning and enumeration
- Updated exploit modules targeting current software versions

## Maintenance

Legacy modules are maintained on a best-effort basis. Bug fixes and critical updates may be applied, but new features are unlikely to be added. Users are encouraged to focus on modern modules and techniques for active security assessments.

## Contributing

When contributing new modules:

- Ensure the disclosure date is current (within the last 4-5 years)
- Avoid duplicating functionality better served by existing tools
- Focus on exploits and techniques relevant to modern systems
- Follow the [Metasploit Framework contribution guidelines](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md)

---

*Last Updated: December 2025*
