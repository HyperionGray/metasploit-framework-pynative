#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Round 9 Fluid Converter - Be Like Water

This is the heart of Round 9: an adaptive conversion engine that flows
like water around any Ruby code structure, never stopping until the
conversion is complete.

"Python is fluid, if you put python in a cup, it takes the shape of the cup.
If python encounters a wall and it has cracks, it flows through the cracks,
it is flexible, it does not stop. It adjusts to the situation it is given."
- Bruce Lee (adapted)
"""

import os
import re
import ast
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from enum import Enum
import traceback

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConversionComplexity(Enum):
    """Levels of Ruby code complexity"""
    SIMPLE = "simple"           # Direct syntax mapping
    MODERATE = "moderate"       # Some pattern matching needed
    COMPLEX = "complex"         # Structural changes required
    INTRICATE = "intricate"     # Advanced Ruby features
    IMPOSSIBLE = "impossible"   # Requires manual intervention

class ObstacleType(Enum):
    """Types of conversion obstacles"""
    METAPROGRAMMING = "metaprogramming"
    RUBY_GEMS = "ruby_gems"
    DSL_PATTERNS = "dsl_patterns"
    COMPLEX_INHERITANCE = "complex_inheritance"
    RUBY_SPECIFIC_SYNTAX = "ruby_specific_syntax"
    THREADING_PATTERNS = "threading_patterns"
    NATIVE_EXTENSIONS = "native_extensions"

@dataclass
class CodeAnalysis:
    """Analysis result of Ruby code structure"""
    complexity_level: ConversionComplexity
    ruby_patterns: List[str]
    dependencies: List[str]
    obstacles: List[ObstacleType]
    recommended_strategy: str
    confidence_score: float
    analysis_notes: List[str]

@dataclass
class ConversionResult:
    """Result of a conversion attempt"""
    success: bool
    python_code: str
    strategy_used: str
    obstacles_encountered: List[ObstacleType]
    obstacles_resolved: List[ObstacleType]
    quality_score: float
    notes: List[str]
    fallback_used: bool = False

class ConversionObstacle(Exception):
    """Exception raised when conversion encounters an obstacle"""
    def __init__(self, obstacle_type: ObstacleType, message: str, ruby_code: str = ""):
        self.obstacle_type = obstacle_type
        self.message = message
        self.ruby_code = ruby_code
        super().__init__(f"{obstacle_type.value}: {message}")

class PatternAnalyzer:
    """
    Analyzes Ruby code patterns to determine optimal conversion strategy.
    Like water testing the shape of its container.
    """
    
    def __init__(self):
        self.ruby_patterns = {
            'class_definition': r'class\s+(\w+)(?:\s*<\s*(\w+(?:::\w+)*))?',
            'module_definition': r'module\s+(\w+)',
            'method_definition': r'def\s+(\w+)(?:\(([^)]*)\))?',
            'attr_accessor': r'attr_(?:accessor|reader|writer)\s+([^#\n]+)',
            'include_statement': r'include\s+(\w+(?:::\w+)*)',
            'require_statement': r'require\s+[\'"]([^\'"]+)[\'"]',
            'metaprogramming': r'(?:define_method|class_eval|instance_eval|send|method_missing)',
            'blocks': r'(?:do\s*\|[^|]*\||{[^}]*})',
            'symbols': r':[a-zA-Z_]\w*',
            'string_interpolation': r'#\{[^}]+\}',
            'ruby_gems': r'(?:Rex::|Msf::)',
            'complex_inheritance': r'class\s+\w+\s*<\s*\w+(?:::\w+)+',
        }
        
    def analyze(self, ruby_code: str) -> CodeAnalysis:
        """
        Analyze Ruby code like water examining its container
        """
        logger.info("🔍 Analyzing Ruby code structure...")
        
        patterns_found = []
        dependencies = []
        obstacles = []
        notes = []
        
        # Pattern detection
        for pattern_name, pattern_regex in self.ruby_patterns.items():
            matches = re.findall(pattern_regex, ruby_code, re.MULTILINE)
            if matches:
                patterns_found.append(pattern_name)
                logger.debug(f"Found pattern: {pattern_name} ({len(matches)} matches)")
        
        # Dependency analysis
        require_matches = re.findall(r'require\s+[\'"]([^\'"]+)[\'"]', ruby_code)
        dependencies.extend(require_matches)
        
        # Obstacle detection
        if 'metaprogramming' in patterns_found:
            obstacles.append(ObstacleType.METAPROGRAMMING)
            notes.append("Metaprogramming detected - will need adaptive approach")
            
        if 'ruby_gems' in patterns_found:
            obstacles.append(ObstacleType.RUBY_GEMS)
            notes.append("Ruby-specific gems detected - will need replacement strategy")
            
        if 'complex_inheritance' in patterns_found:
            obstacles.append(ObstacleType.COMPLEX_INHERITANCE)
            notes.append("Complex inheritance detected - may need restructuring")
        
        # Complexity assessment
        complexity = self._assess_complexity(patterns_found, obstacles, ruby_code)
        
        # Strategy recommendation
        strategy = self._recommend_strategy(complexity, patterns_found, obstacles)
        
        # Confidence scoring
        confidence = self._calculate_confidence(complexity, obstacles)
        
        return CodeAnalysis(
            complexity_level=complexity,
            ruby_patterns=patterns_found,
            dependencies=dependencies,
            obstacles=obstacles,
            recommended_strategy=strategy,
            confidence_score=confidence,
            analysis_notes=notes
        )
    
    def _assess_complexity(self, patterns: List[str], obstacles: List[ObstacleType], code: str) -> ConversionComplexity:
        """Assess the complexity level of Ruby code"""
        
        # Count complexity indicators
        complexity_score = 0
        
        if 'metaprogramming' in patterns:
            complexity_score += 3
        if 'complex_inheritance' in patterns:
            complexity_score += 2
        if 'ruby_gems' in patterns:
            complexity_score += 2
        if len(obstacles) > 2:
            complexity_score += 1
        if len(code.split('\n')) > 200:
            complexity_score += 1
            
        # Determine complexity level
        if complexity_score == 0:
            return ConversionComplexity.SIMPLE
        elif complexity_score <= 2:
            return ConversionComplexity.MODERATE
        elif complexity_score <= 4:
            return ConversionComplexity.COMPLEX
        elif complexity_score <= 6:
            return ConversionComplexity.INTRICATE
        else:
            return ConversionComplexity.IMPOSSIBLE
    
    def _recommend_strategy(self, complexity: ConversionComplexity, patterns: List[str], obstacles: List[ObstacleType]) -> str:
        """Recommend the best conversion strategy"""
        
        if complexity == ConversionComplexity.SIMPLE:
            return "DirectConversionStrategy"
        elif complexity == ConversionComplexity.MODERATE:
            return "PatternMatchingStrategy"
        elif complexity == ConversionComplexity.COMPLEX:
            return "StructuralRewriteStrategy"
        elif complexity == ConversionComplexity.INTRICATE:
            return "HybridBridgeStrategy"
        else:
            return "FallbackTemplateStrategy"
    
    def _calculate_confidence(self, complexity: ConversionComplexity, obstacles: List[ObstacleType]) -> float:
        """Calculate confidence in successful conversion"""
        
        base_confidence = {
            ConversionComplexity.SIMPLE: 0.95,
            ConversionComplexity.MODERATE: 0.85,
            ConversionComplexity.COMPLEX: 0.70,
            ConversionComplexity.INTRICATE: 0.50,
            ConversionComplexity.IMPOSSIBLE: 0.20
        }
        
        confidence = base_confidence[complexity]
        
        # Reduce confidence for each obstacle
        confidence -= len(obstacles) * 0.05
        
        return max(0.1, min(1.0, confidence))

class ObstacleNavigator:
    """
    Navigates around Ruby constructs that resist direct conversion.
    Like water finding cracks in a wall.
    """
    
    def __init__(self):
        self.navigation_strategies = {
            ObstacleType.METAPROGRAMMING: self._handle_metaprogramming,
            ObstacleType.RUBY_GEMS: self._handle_ruby_gems,
            ObstacleType.DSL_PATTERNS: self._handle_dsl_patterns,
            ObstacleType.COMPLEX_INHERITANCE: self._handle_complex_inheritance,
            ObstacleType.RUBY_SPECIFIC_SYNTAX: self._handle_ruby_syntax,
        }
    
    def find_alternative(self, obstacle: ConversionObstacle) -> Optional[str]:
        """
        Find alternative conversion path around an obstacle
        """
        logger.info(f"🌊 Flowing around obstacle: {obstacle.obstacle_type.value}")
        
        if obstacle.obstacle_type in self.navigation_strategies:
            return self.navigation_strategies[obstacle.obstacle_type](obstacle.ruby_code)
        else:
            return self._create_adaptive_wrapper(obstacle.ruby_code)
    
    def _handle_metaprogramming(self, ruby_code: str) -> str:
        """Handle Ruby metaprogramming by creating Python equivalents"""
        logger.info("Adapting metaprogramming patterns...")
        
        # Replace define_method with regular method definitions
        code = re.sub(
            r'define_method\s*\(\s*[\'"](\w+)[\'"]\s*\)\s*do\s*\|([^|]*)\|(.*?)end',
            r'def \1(self, \2):\3',
            ruby_code,
            flags=re.DOTALL
        )
        
        # Replace class_eval with class methods
        code = re.sub(
            r'class_eval\s*do(.*?)end',
            r'# Converted from class_eval\1',
            code,
            flags=re.DOTALL
        )
        
        return code
    
    def _handle_ruby_gems(self, ruby_code: str) -> str:
        """Handle Ruby-specific gems by finding Python equivalents"""
        logger.info("Replacing Ruby gems with Python equivalents...")
        
        gem_replacements = {
            'Rex::Socket': 'socket',
            'Rex::Text': 'lib.rex.text',
            'Msf::Exploit::Remote': 'lib.msf.core.exploit.Exploit',
            'Msf::Auxiliary': 'lib.msf.core.auxiliary.Auxiliary',
            'Rex::Proto::Http': 'requests',
        }
        
        code = ruby_code
        for ruby_gem, python_equiv in gem_replacements.items():
            code = code.replace(ruby_gem, python_equiv)
        
        return code
    
    def _handle_dsl_patterns(self, ruby_code: str) -> str:
        """Handle Ruby DSL patterns"""
        logger.info("Translating DSL patterns...")
        
        # Convert register_options to Python format
        code = re.sub(
            r'register_options\(\[(.*?)\]\)',
            r'self.register_options([\1])',
            ruby_code,
            flags=re.DOTALL
        )
        
        return code
    
    def _handle_complex_inheritance(self, ruby_code: str) -> str:
        """Handle complex Ruby inheritance patterns"""
        logger.info("Simplifying inheritance structure...")
        
        # Simplify complex inheritance chains
        code = re.sub(
            r'class\s+(\w+)\s*<\s*(\w+(?:::\w+)+)',
            r'class \1(Exploit):  # Simplified from \2',
            ruby_code
        )
        
        return code
    
    def _handle_ruby_syntax(self, ruby_code: str) -> str:
        """Handle Ruby-specific syntax"""
        logger.info("Converting Ruby syntax to Python...")
        
        code = ruby_code
        
        # Convert symbols to strings
        code = re.sub(r':(\w+)', r'"\1"', code)
        
        # Convert string interpolation
        code = re.sub(r'#\{([^}]+)\}', r'{{\1}}', code)
        
        # Convert blocks to lambda functions (simplified)
        code = re.sub(r'do\s*\|([^|]*)\|(.*?)end', r'lambda \1: \2', code, flags=re.DOTALL)
        
        return code
    
    def _create_adaptive_wrapper(self, ruby_code: str) -> str:
        """Create an adaptive wrapper for unconvertible code"""
        logger.info("Creating adaptive wrapper for complex code...")
        
        return f'''
# Adaptive wrapper for complex Ruby code
class AdaptiveWrapper:
    """
    This wrapper maintains Ruby functionality while providing Python interface
    """
    
    def __init__(self):
        # Original Ruby code preserved for reference
        self.original_ruby = """
{ruby_code}
"""
        # TODO: Implement Python equivalent functionality
        pass
    
    def execute(self):


