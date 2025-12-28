#!/usr/bin/env python3

"""
Build script for Windows x86 shellcode assembly.

This script assembles various shellcode components (singles, stages, stagers,
egghunters, kernel code) using NASM and outputs binary files along with
useful information such as offsets and hex dumps.

Usage:
    python build.py <name>          # Build specific shellcode
    python build.py all             # Build all shellcode
    python build.py clean           # Clean binary files

Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
"""

import os
import sys
import time
from subprocess import Popen
from struct import pack


def clean(dir='./bin/'):
    """
    Remove all files (except .keep) from the specified directory.

    Args:
        dir: Directory path to clean (default: './bin/')
    """
    for root, dirs, files in os.walk(dir):
        for name in files:
            if name != '.keep':
                os.remove(os.path.join(root, name))


def locate(src_file, dir='./src/'):
    """
    Locate a source file within the source directory tree.

    Args:
        src_file: Name of the source file to locate
        dir: Root directory to search (default: './src/')

    Returns:
        Path to the directory containing the file, or None if not found
    """
    for root, dirs, files in os.walk(dir):
        for name in files:
            if src_file == name:
                return root
    return None


def build(name):
    """
    Build a shellcode binary from assembly source using NASM.

    Assembles the specified .asm file and calls xmit() to output
    information about the resulting binary.

    Args:
        name: Name of the shellcode (without .asm extension)
    """
    location = locate('%s.asm' % name)
    if location:
        input = os.path.normpath(os.path.join(location, name))
        output = os.path.normpath(os.path.join('./bin/', name))
        p = Popen(['nasm', '-f bin', '-O3', '-o %s.bin' %
                   output, '%s.asm' % input])
        p.wait()
        xmit(name)
    else:
        print("[-] Unable to locate '%s.asm' in the src directory" % name)


def xmit_dump_ruby(data, length=16):
    """
    Output binary data as a Ruby-style hex string dump.

    Args:
        data: Binary data to dump
        length: Number of bytes per line (default: 16)
    """
    dump = ''
    for i in range(0, len(data), length):
        bytes = data[i: i+length]
        hex = "\"%s\"" % (''.join(['\\x%02X' % x for x in bytes]))
        if i+length <= len(data):
            hex += ' +'
        dump += '%s\n' % (hex)
    print(dump)


def xmit_offset(data, name, value, match_offset=0):
    """
    Find and print the offset of a specific value in the binary data.

    Args:
        data: Binary data to search
        name: Descriptive name for the offset
        value: Byte sequence to find
        match_offset: Additional offset to add to result (default: 0)
    """
    offset = data.find(value)
    if offset != -1:
        print('# %s Offset: %d' % (name, offset + match_offset))


def xmit(name, dump_ruby=True):
    """
    Output information about a built shellcode binary.

    Prints the name, length, important offsets, and optionally a hex dump
    of the shellcode. Also checks for NULL bytes in egghunter shellcode.

    Args:
        name: Name of the shellcode
        dump_ruby: Whether to output Ruby-style hex dump (default: True)
    """
    bin = os.path.normpath(os.path.join('./bin/', '%s.bin' % name))
    f = open(bin, 'rb')
    data = bytearray(f.read())
    print('# Name: %s\n# Length: %d bytes' % (name, len(data)))
    xmit_offset(data, 'Port', pack('>H', 4444))           # 4444
    xmit_offset(data, 'LEPort', pack('<H', 4444))         # 4444
    xmit_offset(data, 'Host', pack('>L', 0x7F000001))     # 127.0.0.1
    xmit_offset(data, 'IPv6Host', pack(
        '<Q', 0xBBBBBBBBBBBBBBB1))  # An IPv6 Address
    xmit_offset(data, 'IPv6ScopeId', pack(
        '<L', 0xAAAAAAA1))  # An IPv6 Scope ID
    # hostname filler
    xmit_offset(data, 'HostName',
                b'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\x00')
    xmit_offset(data, 'RetryCounter', b'\x6a\x05', 1)     # socket retry
    xmit_offset(data, 'CodeLen', pack('<L', 0x12345678))  # Filler
    xmit_offset(data, 'Hostname', b'https')
    # kernel32.dll!ExitThread
    xmit_offset(data, 'ExitFunk', pack('<L', 0x0A2A1DE0))
    # kernel32.dll!ExitProcess
    xmit_offset(data, 'ExitFunk', pack('<L', 0x56A2B5F0))
    # kernel32.dll!SetUnhandledExceptionFilter
    xmit_offset(data, 'ExitFunk', pack('<L', 0xEA320EFE))
    xmit_offset(data, 'ExitFunk', pack('<L', 0xE035F044))  # kernel32.dll!Sleep
    xmit_offset(data, 'EggTag1', pack('<L', 0xDEADDEAD))  # Egg tag 1
    xmit_offset(data, 'EggTag2', pack('<L', 0xC0DEC0DE))  # Egg tag 2
    xmit_offset(data, 'EggTagSize', pack('>H', 0x1122))   # Egg tag size
    xmit_offset(data, 'RC4Key', b'RC4KeyMetasploit')          # RC4 key
    xmit_offset(data, 'XORKey', b'XORK')                      # XOR key
    if(name.find('egghunter') >= 0):
        null_count = data.count('\x00')
        if(null_count > 0):
            print('# Note: %d NULL bytes found.' % (null_count))
    if dump_ruby:
        xmit_dump_ruby(data)


def main(argv=None):
    """
    Main entry point for the build script.

    Processes command-line arguments and dispatches to appropriate functions.

    Args:
        argv: Command-line arguments (default: sys.argv)
    """
    if not argv:
        argv = sys.argv
        if len(argv) == 1:
            print('Usage: build.py [clean|all|<name>]')
        else:
            print('# Built on %s\n' % (time.asctime(time.localtime())))
            if argv[1] == 'clean':
                clean()
            elif argv[1] == 'all':
                for root, dirs, files in os.walk('./src/egghunter/'):
                    for name in files:
                        build(name[:-4])
                for root, dirs, files in os.walk('./src/migrate/'):
                    for name in files:
                        build(name[:-4])
                for root, dirs, files in os.walk('./src/single/'):
                    for name in files:
                        build(name[:-4])
                for root, dirs, files in os.walk('./src/stage/'):
                    for name in files:
                        build(name[:-4])
                for root, dirs, files in os.walk('./src/stager/'):
                    for name in files:
                        build(name[:-4])
                for root, dirs, files in os.walk('./src/kernel/'):
                    for name in files:
                        build(name[:-4])
            else:
                build(argv[1])

if __name__ == '__main__':
    main()
