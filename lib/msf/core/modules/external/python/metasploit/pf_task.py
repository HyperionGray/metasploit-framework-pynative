#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pf_task.py - pwntools Framework Task Integration for Metasploit

This module provides the core infrastructure for integrating pwntools (pf) 
with Metasploit Framework, enabling task-based exploitation workflows.
"""

import json
import logging
import os
import sys
import importlib
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

from metasploit import module, cli

# Try to import pwntools components
try:
    from pwn import *
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False
    log = lambda *args, **kwargs: None  # Fallback logging

# Try to import additional tools
try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False

class TaskCategory(Enum):
    """Categories for pf tasks"""
    EXPLOIT = "exploit"
    RECON = "recon"
    ANALYSIS = "analysis"
    EDUCATION = "education"
    UTILITY = "utility"
    LEGACY = "legacy"

class SkillLevel(Enum):
    """Skill levels for educational content"""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

@dataclass
class TaskMetadata:
    """Enhanced metadata for pf tasks"""
    name: str
    description: str
    authors: List[str]
    category: TaskCategory
    skill_level: SkillLevel
    date: str
    license: str = 'MSF_LICENSE'
    references: List[Dict[str, str]] = field(default_factory=list)
    targets: List[Dict[str, str]] = field(default_factory=list)
    options: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # pf-specific fields
    tools_required: List[str] = field(default_factory=list)
    educational_objectives: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    estimated_time: str = "5-10 minutes"
    difficulty_rating: int = 1  # 1-5 scale
    
    # Environment configuration
    env_vars: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MSF compatibility"""
        return {
            'name': self.name,
            'description': self.description,
            'authors': self.authors,
            'date': self.date,
            'license': self.license,
            'references': self.references,
            'type': f'pf_{self.category.value}',
            'targets': self.targets,
            'options': self.options,
            'pf_metadata': {
                'category': self.category.value,
                'skill_level': self.skill_level.value,
                'tools_required': self.tools_required,
                'educational_objectives': self.educational_objectives,
                'prerequisites': self.prerequisites,
                'estimated_time': self.estimated_time,
                'difficulty_rating': self.difficulty_rating,
                'env_vars': self.env_vars
            }
        }

class ToolIntegration:
    """Base class for tool integrations"""
    
    def __init__(self, task_context: Dict[str, Any]):
        self.context = task_context
        self.available = False
        
    def check_availability(self) -> bool:
        """Check if tool is available"""
        return self.available
        
    def initialize(self) -> bool:
        """Initialize the tool"""
        return True
        
    def cleanup(self):
        """Cleanup resources"""
        pass

class PwntoolsIntegration(ToolIntegration):
    """pwntools integration wrapper"""
    
    def __init__(self, task_context: Dict[str, Any]):
        super().__init__(task_context)
        self.available = PWNTOOLS_AVAILABLE
        
    def get_context(self) -> Dict[str, Any]:
        """Get pwntools context configuration"""
        if not self.available:
            return {}
            
        return {
            'arch': context.arch,
            'bits': context.bits,
            'endian': context.endian,
            'os': context.os,
            'log_level': context.log_level
        }
        
    def set_context(self, **kwargs):
        """Set pwntools context"""
        if not self.available:
            return
            
        for key, value in kwargs.items():
            if hasattr(context, key):
                setattr(context, key, value)

class RadareIntegration(ToolIntegration):
    """Radare2 integration wrapper"""
    
    def __init__(self, task_context: Dict[str, Any]):
        super().__init__(task_context)
        self.available = R2_AVAILABLE
        self.r2 = None
        
    def initialize(self, binary_path: str = None) -> bool:
        """Initialize radare2 session"""
        if not self.available:
            return False
            
        try:
            if binary_path:
                self.r2 = r2pipe.open(binary_path)
            else:
                self.r2 = r2pipe.open()
            return True
        except Exception as e:
            log.error(f"Failed to initialize radare2: {e}")
            return False
            
    def analyze(self, level: str = "aa") -> Dict[str, Any]:
        """Run analysis"""
        if not self.r2:
            return {}
            
        try:
            self.r2.cmd(level)
            return {
                'functions': self.r2.cmdj('aflj'),
                'strings': self.r2.cmdj('izj'),
                'imports': self.r2.cmdj('iij'),
                'sections': self.r2.cmdj('iSj')
            }
        except Exception as e:
            log.error(f"Analysis failed: {e}")
            return {}
            
    def cleanup(self):
        """Cleanup radare2 session"""
        if self.r2:
            self.r2.quit()
            self.r2 = None

class PfTaskRunner:
    """Main task runner for pf tasks"""
    
    def __init__(self):
        self.tools = {}
        self.current_task = None
        
    def register_tool(self, name: str, tool_class: type):
        """Register a tool integration"""
        self.tools[name] = tool_class
        
    def initialize_tools(self, task_context: Dict[str, Any], required_tools: List[str]) -> Dict[str, ToolIntegration]:
        """Initialize required tools for a task"""
        initialized = {}
        
        for tool_name in required_tools:
            if tool_name in self.tools:
                tool = self.tools[tool_name](task_context)
                if tool.check_availability():
                    if tool.initialize():
                        initialized[tool_name] = tool
                    else:
                        log.warning(f"Failed to initialize {tool_name}")
                else:
                    log.warning(f"Tool {tool_name} not available")
            else:
                log.warning(f"Unknown tool: {tool_name}")
                
        return initialized
        
    def cleanup_tools(self, tools: Dict[str, ToolIntegration]):
        """Cleanup initialized tools"""
        for tool in tools.values():
            try:
                tool.cleanup()
            except Exception as e:
                log.error(f"Error cleaning up tool: {e}")

# Global task runner instance
task_runner = PfTaskRunner()

# Register built-in tool integrations
task_runner.register_tool('pwntools', PwntoolsIntegration)
task_runner.register_tool('radare2', RadareIntegration)

def create_pf_task(metadata: TaskMetadata, 
                   task_function: Callable[[Dict[str, Any]], Any],
                   educational_function: Optional[Callable[[Dict[str, Any]], str]] = None) -> Callable:
    """
    Decorator to create a pf task with enhanced capabilities
    
    Args:
        metadata: Task metadata
        task_function: Main task execution function
        educational_function: Optional function to provide educational content
    
    Returns:
        Wrapped task function compatible with MSF module system
    """
    
    def task_wrapper(args: Dict[str, Any]) -> Any:
        """Wrapper function that handles pf task execution"""
        
        # Set up logging
        module.LogHandler.setup(msg_prefix=f'{metadata.name} - ')
        
        # Check tool availability
        missing_tools = []
        for tool in metadata.tools_required:
            if tool == 'pwntools' and not PWNTOOLS_AVAILABLE:
                missing_tools.append('pwntools')
            elif tool == 'radare2' and not R2_AVAILABLE:
                missing_tools.append('radare2')
                
        if missing_tools:
            logging.error(f'Missing required tools: {", ".join(missing_tools)}')
            return False
            
        # Set up environment variables
        for env_var, default_value in metadata.env_vars.items():
            if env_var not in os.environ:
                os.environ[env_var] = str(args.get(env_var.lower(), default_value))
                
        # Initialize tools
        tools = task_runner.initialize_tools(args, metadata.tools_required)
        
        try:
            # Provide educational content if available
            if educational_function and args.get('show_education', True):
                education_content = educational_function(args)
                if education_content:
                    logging.info("=== Educational Content ===")
                    logging.info(education_content)
                    logging.info("=== Starting Task ===")
                    
            # Execute the main task
            result = task_function(args, tools)
            
            # Log completion
            logging.info(f"Task '{metadata.name}' completed successfully")
            return result
            
        except Exception as e:
            logging.error(f"Task failed: {e}")
            return False
        finally:
            # Cleanup tools
            task_runner.cleanup_tools(tools)
    
    return task_wrapper

def run_pf_task(metadata: TaskMetadata, 
                task_function: Callable[[Dict[str, Any]], Any],
                educational_function: Optional[Callable[[Dict[str, Any]], str]] = None):
    """
    Run a pf task using the MSF module system
    
    Args:
        metadata: Task metadata
        task_function: Main task execution function  
        educational_function: Optional educational content function
    """
    
    # Create the wrapped task function
    wrapped_task = create_pf_task(metadata, task_function, educational_function)
    
    # Convert metadata to MSF format
    msf_metadata = metadata.to_dict()
    
    # Run using MSF module system
    module.run(msf_metadata, wrapped_task)

# Utility functions for common pf task patterns

def setup_pwntools_context(target_info: Dict[str, Any]) -> bool:
    """Setup pwntools context based on target information"""
    if not PWNTOOLS_AVAILABLE:
        return False
        
    try:
        if 'arch' in target_info:
            context.arch = target_info['arch']
        if 'bits' in target_info:
            context.bits = target_info['bits']
        if 'endian' in target_info:
            context.endian = target_info['endian']
        if 'os' in target_info:
            context.os = target_info['os']
            
        # Set reasonable defaults
        context.log_level = 'info'
        return True
    except Exception as e:
        log.error(f"Failed to setup pwntools context: {e}")
        return False

def create_rop_chain(binary_path: str, gadgets_needed: List[str]) -> Optional[Any]:
    """Create ROP chain using pwntools"""
    if not PWNTOOLS_AVAILABLE:
        return None
        
    try:
        elf = ELF(binary_path)
        rop = ROP(elf)
        
        # This is a simplified example - real implementation would be more sophisticated
        for gadget in gadgets_needed:
            if hasattr(rop, gadget):
                getattr(rop, gadget)()
                
        return rop
    except Exception as e:
        log.error(f"Failed to create ROP chain: {e}")
        return None

def analyze_binary_with_radare(binary_path: str) -> Dict[str, Any]:
    """Analyze binary using radare2 integration"""
    if not R2_AVAILABLE:
        return {}
        
    radare = RadareIntegration({})
    if radare.initialize(binary_path):
        try:
            return radare.analyze()
        finally:
            radare.cleanup()
    return {}

# Educational content helpers

def create_educational_content(objectives: List[str], 
                             concepts: List[str],
                             steps: List[str]) -> str:
    """Create formatted educational content"""
    content = []
    
    if objectives:
        content.append("Learning Objectives:")
        for obj in objectives:
            content.append(f"  • {obj}")
        content.append("")
        
    if concepts:
        content.append("Key Concepts:")
        for concept in concepts:
            content.append(f"  • {concept}")
        content.append("")
        
    if steps:
        content.append("Task Steps:")
        for i, step in enumerate(steps, 1):
            content.append(f"  {i}. {step}")
        content.append("")
        
    return "\n".join(content)

# Environment variable helpers

def get_env_config(prefix: str = "PF_") -> Dict[str, str]:
    """Get all environment variables with given prefix"""
    return {
        key[len(prefix):].lower(): value 
        for key, value in os.environ.items() 
        if key.startswith(prefix)
    }

def set_env_defaults(defaults: Dict[str, str], prefix: str = "PF_"):
    """Set default environment variables if not already set"""
    for key, value in defaults.items():
        env_key = f"{prefix}{key.upper()}"
        if env_key not in os.environ:
            os.environ[env_key] = value