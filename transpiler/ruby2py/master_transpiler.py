#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Master Transpilation Script
Run the transpiler on EVERY Ruby file and convert all configs to Python.

This is the main script that orchestrates the complete Ruby to Python migration:
1. Transpile ALL .rb files to .py files
2. Convert Ruby configs to Python configs
3. Generate migration report
4. Verify Ruby is dead, long live Python!
"""

import os
import sys
import subprocess
import logging
from pathlib import Path
from datetime import datetime
import argparse

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MasterTranspiler:
    """Master orchestrator for complete Ruby to Python migration"""
    
    def __init__(self, repo_root: Path = None, dry_run: bool = False, skip_existing: bool = True):
        if repo_root is None:
            repo_root = Path(__file__).parent.parent.parent
        self.repo_root = repo_root
        self.dry_run = dry_run
        self.skip_existing = skip_existing
        self.start_time = datetime.now()
        
        # Scripts (updated paths)
        self.transpiler_script = Path(__file__).parent / "comprehensive_transpiler.py"
        self.config_converter_script = repo_root / "convert_configs_to_python.py"