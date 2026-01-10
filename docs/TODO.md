# TODO - Remaining Work Items

This document tracks remaining work items for the complete Ruby to Python conversion of Metasploit Framework.

**Last Updated**: 2026-01-10  
**Verification Status**: ✅ All main commands tested and verified

## Completed ✅

### Phase 1: Ruby Compatibility Removal (Completed)
- ✅ Removed Ruby compatibility wrappers from all main executables
- ✅ Converted msfrpc to native Python implementation
- ✅ Converted msfrpcd to native Python implementation
- ✅ Converted msfd to native Python implementation
- ✅ Converted msfdb to native Python implementation
- ✅ Converted msfupdate to native Python implementation
- ✅ Updated msfrc to remove Ruby fallback logic
- ✅ Moved all Ruby .rb files to bak/root_rb_files/
- ✅ Moved duplicate .py files to bak/py_duplicates/
- ✅ Comprehensive testing of all MSF commands (18/18 tests passing)
- ✅ Verification document created (docs/MSF_SUITE_VERIFICATION.md)

### Main Executables Status
All main executables are now pure Python with no Ruby delegation:
- ✅ `msfconsole` - Pure Python (guides users to use `source msfrc`)
- ✅ `msfvenom` - Pure Python (ELF generation working, full payload library TODO)
- ✅ `msf` - Pure Python (full CLI implementation with workspace management)
- ✅ `msfrpc` - Pure Python (stub implementation)
- ✅ `msfrpcd` - Pure Python (stub implementation)
- ✅ `msfd` - Pure Python (stub implementation)
- ✅ `msfdb` - Pure Python (basic functionality implemented)
- ✅ `msfupdate` - Pure Python (git update functionality implemented)
- ✅ `msfrc` - Pure bash (full environment activation, no Ruby fallbacks)

## Remaining Work 🚧

### Phase 2: Framework Core Implementation

#### High Priority
1. **Python Framework Core** (lib/msf/)
   - Implement core framework classes in Python
   - Module loader and manager
   - Session management
   - Database connectivity layer
   - Configuration management

2. **Interactive Console** (msfconsole)
   - Full console implementation with readline support
   - Command parser and dispatcher
   - Tab completion
   - History management
   - Module interaction interface

3. **Payload Generation** (msfvenom)
   - Full payload generation engine
   - Encoder support
   - Template injection
   - Format transformations
   - All payload types (staged, stageless, singles)

#### Medium Priority
4. **RPC Infrastructure**
   - Complete RPC server implementation (msfrpcd)
   - RPC client implementation (msfrpc)
   - MSGPACK-RPC protocol support
   - JSON-RPC protocol support
   - Authentication and authorization

5. **Daemon Service** (msfd)
   - Multi-client console daemon
   - Session sharing
   - Client management
   - Security controls (allow/deny lists)

6. **Database Management** (msfdb)
   - Full PostgreSQL management
   - Database schema migration
   - Backup/restore functionality
   - Connection pooling
   - Web service integration

#### Low Priority
7. **Module Testing**
   - Test all converted modules
   - Verify payload functionality
   - Validate exploit modules
   - Check auxiliary modules
   - Post-exploitation module verification

8. **Documentation Updates**
   - Update all references from Ruby to Python
   - Module writing guide for Python
   - API documentation
   - Migration guide for module developers

### Phase 3: External Dependencies

#### Ruby Files in External/
The following Ruby files in external/ are kept as they are external dependencies:
- `external/serialport/extconf.rb` - Serial port configuration
- `external/serialport/test/miniterm.rb` - Test script
- `external/source/*/*.rb` - Various build/test scripts for external tools

**Decision**: These can remain as they are external build/helper scripts, not part of the core framework.

### Phase 4: Testing & Quality

9. **Integration Testing**
   - End-to-end workflow tests
   - Multi-module interaction tests
   - Session handling tests
   - Database integration tests

10. **Performance Optimization**
    - Startup time optimization
    - Module loading performance
    - Memory usage profiling
    - Network performance tuning

11. **Security Hardening**
    - Input validation
    - Command injection prevention
    - SQL injection prevention
    - Secure credential storage

## Implementation Notes

### What Works Now
- Basic msfvenom payload listing (platforms, architectures, formats)
- Basic msfdb database configuration management
- msfupdate git-based updates
- msfrc environment activation
- Module execution via direct Python invocation

### What Needs Implementation
- Full console with framework integration
- Complete payload generation pipeline
- RPC server/client communication
- Multi-client daemon
- Advanced database operations

### Architecture Decisions
1. **Python-First Approach**: All new code written in Python, no Ruby code generation
2. **Modular Design**: Framework core separate from tools
3. **API Compatibility**: Maintain similar API to original MSF where practical
4. **Modern Python**: Use Python 3.8+ features (type hints, dataclasses, asyncio)

## Timeline Estimate

- **Core Framework**: 4-6 weeks
- **Interactive Console**: 2-3 weeks
- **Full Payload Generation**: 3-4 weeks
- **RPC Infrastructure**: 2-3 weeks
- **Testing & Documentation**: 2-3 weeks

**Total Estimated Effort**: 13-19 weeks of development time

## Contributing

To contribute to any of these items:
1. Check this TODO for available work
2. Claim an item by opening an issue
3. Follow Python coding standards (PEP 8, type hints)
4. Write tests for new functionality
5. Update documentation

## Notes

- Ruby files have been moved to `bak/` directories but not deleted
- External Ruby files (in `external/`) are intentionally kept
- All main executables are now pure Python (no Ruby execution)
- msfrc environment activation is the recommended usage pattern
