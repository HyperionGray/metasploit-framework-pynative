# -*- coding: utf-8 -*-
"""
Metasploit Framework Constants

This module defines constants used throughout the framework,
including rankings, architectures, platforms, and other enums.
"""

# Module Rankings
class Ranking:
    """Module reliability rankings."""
    MANUAL = 0
    LOW = 100
    AVERAGE = 200
    NORMAL = 300
    GOOD = 400
    GREAT = 500
    EXCELLENT = 600

# Ranking constants for backward compatibility
ManualRanking = Ranking.MANUAL
LowRanking = Ranking.LOW
AverageRanking = Ranking.AVERAGE
NormalRanking = Ranking.NORMAL
GoodRanking = Ranking.GOOD
GreatRanking = Ranking.GREAT
ExcellentRanking = Ranking.EXCELLENT

# Architectures
class Architecture:
    """Target architectures."""
    X86 = "x86"
    X64 = "x64"
    X86_64 = "x86_64"
    ARM = "arm"
    ARMLE = "armle"
    ARMBE = "armbe"
    AARCH64 = "aarch64"
    MIPS = "mips"
    MIPSLE = "mipsle"
    MIPSBE = "mipsbe"
    PPC = "ppc"
    SPARC = "sparc"
    CMD = "cmd"

# Architecture constants for backward compatibility
ARCH_X86 = Architecture.X86
ARCH_X64 = Architecture.X64
ARCH_X86_64 = Architecture.X86_64
ARCH_ARM = Architecture.ARM
ARCH_ARMLE = Architecture.ARMLE
ARCH_ARMBE = Architecture.ARMBE
ARCH_AARCH64 = Architecture.AARCH64
ARCH_MIPS = Architecture.MIPS
ARCH_MIPSLE = Architecture.MIPSLE
ARCH_MIPSBE = Architecture.MIPSBE
ARCH_PPC = Architecture.PPC
ARCH_SPARC = Architecture.SPARC
ARCH_CMD = Architecture.CMD

# Platforms
class Platform:
    """Target platforms."""
    WINDOWS = "windows"
    LINUX = "linux"
    OSX = "osx"
    UNIX = "unix"
    BSD = "bsd"
    SOLARIS = "solaris"
    AIX = "aix"
    ANDROID = "android"
    IOS = "ios"
    JAVA = "java"
    PHP = "php"
    PYTHON = "python"
    RUBY = "ruby"
    NODEJS = "nodejs"

# Platform constants for backward compatibility
PLATFORM_WINDOWS = Platform.WINDOWS
PLATFORM_LINUX = Platform.LINUX
PLATFORM_OSX = Platform.OSX
PLATFORM_UNIX = Platform.UNIX

# Module Stability
class Stability:
    """Module stability indicators."""
    CRASH_SAFE = "crash-safe"
    CRASH_SERVICE = "crash-service"
    CRASH_OS = "crash-os"
    CRASH_OS_DOWN = "crash-os-down"
    CRASH_OS_RESTARTS = "crash-os-restarts"

CRASH_SAFE = Stability.CRASH_SAFE
CRASH_SERVICE = Stability.CRASH_SERVICE
CRASH_OS = Stability.CRASH_OS
CRASH_OS_DOWN = Stability.CRASH_OS_DOWN
CRASH_OS_RESTARTS = Stability.CRASH_OS_RESTARTS

# Module Reliability
class Reliability:
    """Module reliability indicators."""
    FIRST_ATTEMPT = "first-attempt"
    REPEATABLE_SESSION = "repeatable-session"
    UNRELIABLE_SESSION = "unreliable-session"

FIRST_ATTEMPT = Reliability.FIRST_ATTEMPT
REPEATABLE_SESSION = Reliability.REPEATABLE_SESSION
UNRELIABLE_SESSION = Reliability.UNRELIABLE_SESSION

# Side Effects
class SideEffects:
    """Module side effects."""
    ARTIFACTS_ON_DISK = "artifacts-on-disk"
    CONFIG_CHANGES = "config-changes"
    IOC_IN_LOGS = "ioc-in-logs"
    SCREEN_EFFECTS = "screen-effects"
    ACCOUNT_LOCKOUTS = "account-lockouts"

ARTIFACTS_ON_DISK = SideEffects.ARTIFACTS_ON_DISK
CONFIG_CHANGES = SideEffects.CONFIG_CHANGES
IOC_IN_LOGS = SideEffects.IOC_IN_LOGS
SCREEN_EFFECTS = SideEffects.SCREEN_EFFECTS
ACCOUNT_LOCKOUTS = SideEffects.ACCOUNT_LOCKOUTS

# License
MSF_LICENSE = "Metasploit Framework License (BSD)"

# Default ports
DEFAULT_PORTS = {
    'http': 80,
    'https': 443,
    'ssh': 22,
    'telnet': 23,
    'ftp': 21,
    'smtp': 25,
    'pop3': 110,
    'imap': 143,
    'snmp': 161,
    'ldap': 389,
    'smb': 445,
    'mssql': 1433,
    'mysql': 3306,
    'postgresql': 5432,
    'vnc': 5900,
    'rdp': 3389
}