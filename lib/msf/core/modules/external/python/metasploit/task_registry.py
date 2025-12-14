#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
task_registry.py - Task Discovery and Registry System for pf Tasks

This module provides task discovery, categorization, and filtering capabilities
for the pf (pwntools framework) integration with Metasploit.
"""

import os
import sys
import json
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

from .pf_task import TaskMetadata, TaskCategory, SkillLevel

@dataclass
class TaskInfo:
    """Information about a registered task"""
    name: str
    path: str
    metadata: TaskMetadata
    module_name: str
    last_updated: datetime
    success_rate: float = 0.0
    usage_count: int = 0
    user_rating: float = 0.0
    is_deprecated: bool = False
    deprecation_reason: str = ""

class TaskFilter:
    """Filter for task discovery and selection"""
    
    def __init__(self):
        self.categories: Set[TaskCategory] = set()
        self.skill_levels: Set[SkillLevel] = set()
        self.tools_required: Set[str] = set()
        self.min_rating: float = 0.0
        self.max_difficulty: int = 5
        self.include_deprecated: bool = False
        self.include_legacy: bool = False
        self.search_terms: List[str] = []
        
    def matches(self, task_info: TaskInfo) -> bool:
        """Check if task matches filter criteria"""
        metadata = task_info.metadata
        
        # Category filter
        if self.categories and metadata.category not in self.categories:
            return False
            
        # Skill level filter
        if self.skill_levels and metadata.skill_level not in self.skill_levels:
            return False
            
        # Tools filter
        if self.tools_required:
            task_tools = set(metadata.tools_required)
            if not self.tools_required.issubset(task_tools):
                return False
                
        # Rating filter
        if task_info.user_rating < self.min_rating:
            return False
            
        # Difficulty filter
        if metadata.difficulty_rating > self.max_difficulty:
            return False
            
        # Deprecated filter
        if task_info.is_deprecated and not self.include_deprecated:
            return False
            
        # Legacy filter
        if metadata.category == TaskCategory.LEGACY and not self.include_legacy:
            return False
            
        # Search terms
        if self.search_terms:
            searchable_text = f"{metadata.name} {metadata.description} {' '.join(metadata.authors)}".lower()
            for term in self.search_terms:
                if term.lower() not in searchable_text:
                    return False
                    
        return True

class TaskRegistry:
    """Registry for pf tasks with discovery and filtering capabilities"""
    
    def __init__(self, base_paths: List[str] = None):
        self.tasks: Dict[str, TaskInfo] = {}
        self.base_paths = base_paths or []
        self.stats_file = os.path.expanduser("~/.msf_pf_task_stats.json")
        self.load_stats()
        
    def add_base_path(self, path: str):
        """Add a base path for task discovery"""
        if path not in self.base_paths:
            self.base_paths.append(path)
            
    def discover_tasks(self, force_refresh: bool = False) -> int:
        """Discover tasks in base paths"""
        discovered_count = 0
        
        for base_path in self.base_paths:
            discovered_count += self._discover_in_path(base_path, force_refresh)
            
        self.save_stats()
        return discovered_count
        
    def _discover_in_path(self, base_path: str, force_refresh: bool) -> int:
        """Discover tasks in a specific path"""
        discovered_count = 0
        path_obj = Path(base_path)
        
        if not path_obj.exists():
            return 0
            
        # Look for Python files that might contain pf tasks
        for py_file in path_obj.rglob("*.py"):
            if py_file.name.startswith("__"):
                continue
                
            try:
                task_info = self._analyze_task_file(py_file, force_refresh)
                if task_info:
                    self.tasks[task_info.name] = task_info
                    discovered_count += 1
            except Exception as e:
                # Silently skip files that can't be analyzed
                pass
                
        return discovered_count
        
    def _analyze_task_file(self, file_path: Path, force_refresh: bool) -> Optional[TaskInfo]:
        """Analyze a Python file to see if it contains a pf task"""
        
        # Check if we've already analyzed this file recently
        if not force_refresh:
            existing_task = self._find_task_by_path(str(file_path))
            if existing_task and self._is_file_unchanged(file_path, existing_task):
                return existing_task
                
        try:
            # Read the file and look for pf task patterns
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Look for pf task imports and metadata
            if 'from metasploit.pf_task import' not in content and 'import metasploit.pf_task' not in content:
                return None
                
            # Try to import and analyze the module
            module_name = self._path_to_module_name(file_path)
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if not spec or not spec.loader:
                return None
                
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Look for task metadata
            metadata = None
            if hasattr(module, 'task_metadata'):
                metadata = module.task_metadata
            elif hasattr(module, 'metadata'):
                # Try to convert traditional MSF metadata to TaskMetadata
                metadata = self._convert_msf_metadata(module.metadata)
                
            if not metadata or not isinstance(metadata, TaskMetadata):
                return None
                
            # Create TaskInfo
            task_info = TaskInfo(
                name=metadata.name,
                path=str(file_path),
                metadata=metadata,
                module_name=module_name,
                last_updated=datetime.fromtimestamp(file_path.stat().st_mtime)
            )
            
            # Load existing stats if available
            existing_task = self._find_task_by_path(str(file_path))
            if existing_task:
                task_info.success_rate = existing_task.success_rate
                task_info.usage_count = existing_task.usage_count
                task_info.user_rating = existing_task.user_rating
                task_info.is_deprecated = existing_task.is_deprecated
                task_info.deprecation_reason = existing_task.deprecation_reason
                
            return task_info
            
        except Exception as e:
            return None
            
    def _path_to_module_name(self, file_path: Path) -> str:
        """Convert file path to module name"""
        # Simple conversion - could be more sophisticated
        return str(file_path.stem)
        
    def _convert_msf_metadata(self, msf_metadata: Dict[str, Any]) -> Optional[TaskMetadata]:
        """Convert traditional MSF metadata to TaskMetadata"""
        try:
            # Determine category based on type
            module_type = msf_metadata.get('type', '')
            if 'exploit' in module_type:
                category = TaskCategory.EXPLOIT
            elif 'auxiliary' in module_type:
                category = TaskCategory.UTILITY
            else:
                category = TaskCategory.UTILITY
                
            # Create TaskMetadata
            return TaskMetadata(
                name=msf_metadata.get('name', 'Unknown'),
                description=msf_metadata.get('description', ''),
                authors=msf_metadata.get('authors', []),
                category=category,
                skill_level=SkillLevel.INTERMEDIATE,  # Default
                date=msf_metadata.get('date', ''),
                license=msf_metadata.get('license', 'MSF_LICENSE'),
                references=msf_metadata.get('references', []),
                targets=msf_metadata.get('targets', []),
                options=msf_metadata.get('options', {}),
                tools_required=['pwntools'],  # Default assumption
                educational_objectives=[],
                prerequisites=[],
                estimated_time="Unknown",
                difficulty_rating=3,  # Default medium difficulty
                env_vars={}
            )
        except Exception:
            return None
            
    def _find_task_by_path(self, path: str) -> Optional[TaskInfo]:
        """Find task by file path"""
        for task in self.tasks.values():
            if task.path == path:
                return task
        return None
        
    def _is_file_unchanged(self, file_path: Path, task_info: TaskInfo) -> bool:
        """Check if file has been modified since last analysis"""
        try:
            file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
            return file_mtime <= task_info.last_updated
        except Exception:
            return False
            
    def get_tasks(self, task_filter: Optional[TaskFilter] = None) -> List[TaskInfo]:
        """Get tasks matching filter criteria"""
        if not task_filter:
            return list(self.tasks.values())
            
        return [task for task in self.tasks.values() if task_filter.matches(task)]
        
    def get_task(self, name: str) -> Optional[TaskInfo]:
        """Get specific task by name"""
        return self.tasks.get(name)
        
    def get_categories(self) -> List[TaskCategory]:
        """Get all available task categories"""
        categories = set()
        for task in self.tasks.values():
            categories.add(task.metadata.category)
        return sorted(list(categories), key=lambda x: x.value)
        
    def get_tools_used(self) -> List[str]:
        """Get all tools used by tasks"""
        tools = set()
        for task in self.tasks.values():
            tools.update(task.metadata.tools_required)
        return sorted(list(tools))
        
    def update_task_stats(self, task_name: str, success: bool, rating: Optional[float] = None):
        """Update task statistics"""
        task = self.tasks.get(task_name)
        if not task:
            return
            
        # Update usage count
        task.usage_count += 1
        
        # Update success rate
        if task.usage_count == 1:
            task.success_rate = 1.0 if success else 0.0
        else:
            # Weighted average
            old_successes = task.success_rate * (task.usage_count - 1)
            new_successes = old_successes + (1 if success else 0)
            task.success_rate = new_successes / task.usage_count
            
        # Update rating
        if rating is not None:
            if task.user_rating == 0.0:
                task.user_rating = rating
            else:
                # Simple average for now
                task.user_rating = (task.user_rating + rating) / 2
                
        self.save_stats()
        
    def deprecate_task(self, task_name: str, reason: str):
        """Mark a task as deprecated"""
        task = self.tasks.get(task_name)
        if task:
            task.is_deprecated = True
            task.deprecation_reason = reason
            self.save_stats()
            
    def load_stats(self):
        """Load task statistics from file"""
        try:
            if os.path.exists(self.stats_file):
                with open(self.stats_file, 'r') as f:
                    stats = json.load(f)
                    
                # Update task stats
                for task_name, task_stats in stats.get('tasks', {}).items():
                    if task_name in self.tasks:
                        task = self.tasks[task_name]
                        task.success_rate = task_stats.get('success_rate', 0.0)
                        task.usage_count = task_stats.get('usage_count', 0)
                        task.user_rating = task_stats.get('user_rating', 0.0)
                        task.is_deprecated = task_stats.get('is_deprecated', False)
                        task.deprecation_reason = task_stats.get('deprecation_reason', '')
        except Exception:
            pass  # Ignore errors loading stats
            
    def save_stats(self):
        """Save task statistics to file"""
        try:
            stats = {
                'last_updated': datetime.now().isoformat(),
                'tasks': {}
            }
            
            for task_name, task in self.tasks.items():
                stats['tasks'][task_name] = {
                    'success_rate': task.success_rate,
                    'usage_count': task.usage_count,
                    'user_rating': task.user_rating,
                    'is_deprecated': task.is_deprecated,
                    'deprecation_reason': task.deprecation_reason
                }
                
            with open(self.stats_file, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception:
            pass  # Ignore errors saving stats

# Global registry instance
task_registry = TaskRegistry()

def register_task_paths():
    """Register default task paths"""
    # Add MSF module paths
    msf_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    task_registry.add_base_path(os.path.join(msf_root, 'modules'))
    
    # Add pf tasks directory if it exists
    pf_tasks_dir = os.path.join(msf_root, 'pf_tasks')
    if os.path.exists(pf_tasks_dir):
        task_registry.add_base_path(pf_tasks_dir)
        
    # Add user tasks directory
    user_tasks_dir = os.path.expanduser('~/.msf_pf_tasks')
    if os.path.exists(user_tasks_dir):
        task_registry.add_base_path(user_tasks_dir)

# Initialize default paths
register_task_paths()