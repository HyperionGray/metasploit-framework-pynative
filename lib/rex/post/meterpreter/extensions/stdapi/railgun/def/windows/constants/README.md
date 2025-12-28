# Windows API Constants - Modular Organization

This directory contains Windows API constants organized by functional categories.
Each file contains constants related to a specific area of the Windows API.

## Categories

- `errors.rb` - Windows error codes (ERROR_*, WSAE*, etc.)
- `windows.rb` - Window messages and UI constants (WM_*, etc.)
- `registry.rb` - Registry constants (HKEY_*, REG_*, etc.)
- `security.rb` - Security and cryptography constants (CERT_*, CRYPT_*, SEC_*, etc.)
- `filesystem.rb` - File system constants (FILE_*, DRIVE_*, VOLUME_*, etc.)
- `network.rb` - Network constants (HTTP_*, DNS_*, TCP_*, UDP_*, IP_*, etc.)
- `database.rb` - Database constants (SQL_*, DB_*, etc.)
- `graphics.rb` - Graphics and DirectX constants (DD*, D3D*, GDI*, IMAGE_*, etc.)
- `system.rb` - System and hardware constants (PROCESSOR_*, DEVICE_*, etc.)
- `process.rb` - Process and thread constants (JOB_*, THREAD_*, PROCESS_*, etc.)
- `miscellaneous.rb` - Other constants that don't fit into specific categories

## Usage

The constants are automatically loaded by the main `api_constants.rb` file.
Each category file defines a module that can be included to add its constants
to the constant manager.