#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Base Module class for all Metasploit modules
"""

from typing import Dict, Any, Optional, List


class Module:
    """
    Base class for all Metasploit modules (exploits, auxiliary, post, etc.)
    
    This provides the common interface for module metadata, options, and execution.
    """
    
    # Module ranking constants
    ManualRanking = 0
    LowRanking = 100
    AverageRanking = 200
    NormalRanking = 300
    GoodRanking = 400
    GreatRanking = 500
    ExcellentRanking = 600
    
    # Architecture constants
    ARCH_X86 = 'x86'
    ARCH_X64 = 'x64'
    ARCH_X86_64 = 'x86_64'
    ARCH_MIPS = 'mips'
    ARCH_MIPSLE = 'mipsle'
    ARCH_MIPS64 = 'mips64'
    ARCH_ARM = 'armle'
    ARCH_ARMLE = 'armle'
    ARCH_ARMBE = 'armbe'
    ARCH_AARCH64 = 'aarch64'
    ARCH_PPC = 'ppc'
    ARCH_PPC64 = 'ppc64'
    ARCH_CMD = 'cmd'
    ARCH_PHP = 'php'
    ARCH_TTY = 'tty'
    ARCH_JAVA = 'java'
    ARCH_RUBY = 'ruby'
    ARCH_DALVIK = 'dalvik'
    ARCH_PYTHON = 'python'
    ARCH_NODEJS = 'nodejs'
    ARCH_FIREFOX = 'firefox'
    ARCH_ZARCH = 'zarch'
    
    # Platform constants  
    PLATFORM_WINDOWS = 'win'
    PLATFORM_LINUX = 'linux'
    PLATFORM_OSX = 'osx'
    PLATFORM_UNIX = 'unix'
    PLATFORM_BSD = 'bsd'
    PLATFORM_SOLARIS = 'solaris'
    PLATFORM_ANDROID = 'android'
    PLATFORM_APPLE_IOS = 'apple_ios'
    PLATFORM_JAVA = 'java'
    PLATFORM_RUBY = 'ruby'
    PLATFORM_PHP = 'php'
    PLATFORM_PYTHON = 'python'
    PLATFORM_NODEJS = 'nodejs'
    PLATFORM_FIREFOX = 'firefox'
    PLATFORM_MAINFRAME = 'mainframe'
    
    # Reliability constants
    FIRST_ATTEMPT_FAIL = 'first-attempt-fail'
    REPEATABLE_SESSION = 'repeatable-session'
    UNRELIABLE_SESSION = 'unreliable-session'
    
    # Stability constants
    CRASH_SAFE = 'crash-safe'
    CRASH_SERVICE_RESTARTS = 'crash-service-restarts'
    CRASH_SERVICE_DOWN = 'crash-service-down'
    CRASH_OS_DOWN = 'crash-os-down'
    CRASH_OS_RESTARTS = 'crash-os-restarts'
    
    # Side effects constants
    ARTIFACTS_ON_DISK = 'artifacts-on-disk'
    CONFIG_CHANGES = 'config-changes'
    IOC_IN_LOGS = 'ioc-in-logs'
    SCREEN_EFFECTS = 'screen-effects'
    AUDIO_EFFECTS = 'audio-effects'
    PHYSICAL_EFFECTS = 'physical-effects'
    
    def __init__(self, info: Optional[Dict[str, Any]] = None):
        """
        Initialize the module with metadata
        
        Args:
            info: Module metadata dictionary containing Name, Description, Author, etc.
        """
        self.info = info or {}
        self.options = {}
        self.datastore = {}
        self.framework = None
        
    def initialize(self, info: Dict[str, Any]):
        """
        Initialize module with info hash (Ruby compatibility)
        
        Args:
            info: Module metadata
        """
        self.info = self.update_info(self.info, info)
        
    def update_info(self, base_info: Dict[str, Any], new_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update module info (merge dictionaries)
        
        Args:
            base_info: Base information dictionary
            new_info: New information to merge
            
        Returns:
            Merged dictionary
        """
        result = base_info.copy()
        result.update(new_info)
        return result
        
    def register_options(self, options: List[Any]):
        """
        Register module options
        
        Args:
            options: List of option objects
        """
        for opt in options:
            self.options[opt.name] = opt
            
    def register_advanced_options(self, options: List[Any]):
        """
        Register advanced module options
        
        Args:
            options: List of advanced option objects
        """
        self.register_options(options)
        
    def print_status(self, msg: str):
        """Print status message"""
        print(f"[*] {msg}")
        
    def print_good(self, msg: str):
        """Print success message"""
        print(f"[+] {msg}")
        
    def print_error(self, msg: str):
        """Print error message"""
        print(f"[-] {msg}")
        
    def print_warning(self, msg: str):
        """Print warning message"""
        print(f"[!] {msg}")
        
    def vprint_status(self, msg: str):
        """Print verbose status message"""
        if self.datastore.get('VERBOSE', False):
            self.print_status(msg)
            
    def vprint_good(self, msg: str):
        """Print verbose success message"""
        if self.datastore.get('VERBOSE', False):
            self.print_good(msg)
            
    def vprint_error(self, msg: str):
        """Print verbose error message"""
        if self.datastore.get('VERBOSE', False):
            self.print_error(msg)
            
    def fail_with(self, reason: str, msg: str):
        """
        Fail the module with a specific reason
        
        Args:
            reason: Failure reason constant
            msg: Error message
        """
        self.print_error(f"{reason}: {msg}")
        raise Exception(f"{reason}: {msg}")
        
    @property
    def name(self) -> str:
        """Get module name"""
        return self.info.get('Name', 'Unknown')
        
    @property
    def fullname(self) -> str:
        """Get full module path"""
        return self.info.get('FullName', 'unknown/module')
        
    @property
    def description(self) -> str:
        """Get module description"""
        return self.info.get('Description', '')
        
    @property
    def references(self) -> List[Dict[str, str]]:
        """Get module references"""
        return self.info.get('References', [])
        
    def rhost(self) -> Optional[str]:
        """Get remote host from datastore"""
        return self.datastore.get('RHOST')
        
    def rport(self) -> Optional[int]:
        """Get remote port from datastore"""
        return self.datastore.get('RPORT')
        
    def target_uri(self) -> str:
        """Get target URI from datastore"""
        return self.datastore.get('TARGETURI', '/')
        
    def normalize_uri(self, *parts: str) -> str:
        """
        Normalize URI parts into a proper path
        
        Args:
            parts: URI components to join
            
        Returns:
            Normalized URI path
        """
        path = '/'.join(str(p).strip('/') for p in parts if p)
        if not path.startswith('/'):
            path = '/' + path
        return path
