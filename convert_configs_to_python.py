#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ruby Config to Python Config Converter

Converts Ruby-specific configuration files to Python equivalents:
- Gemfile -> requirements.txt / pyproject.toml
- Rakefile -> Python task files
- .ruby-version -> .python-version
- .rubocop.yml -> .flake8 / pyproject.toml
- config/*.rb files -> Python config files
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, List
import yaml
import re

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ConfigConverter:
    """Convert Ruby configs to Python equivalents"""
    
    def __init__(self, repo_root: Path, dry_run: bool = False):
        self.repo_root = repo_root
        self.dry_run = dry_run
        self.conversions = []
        
    def convert_gemfile_to_requirements(self):
        """Convert Gemfile to requirements.txt"""
        gemfile = self.repo_root / "Gemfile"
        requirements_txt = self.repo_root / "requirements.txt"
        
        if not gemfile.exists():
            logger.info("No Gemfile found, skipping")
            return
        
        logger.info("Converting Gemfile to requirements.txt...")
        
        # Read Gemfile
        with open(gemfile, 'r') as f:
            gemfile_content = f.read()
        
        # Extract gem dependencies
        gem_pattern = re.compile(r"gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?")
        gems = gem_pattern.findall(gemfile_content)
        
        # Map Ruby gems to Python packages (common ones)
        gem_to_python = {
            'rails': 'django',
            'rack': 'werkzeug',
            'sinatra': 'flask',
            'nokogiri': 'lxml',
            'json': '',  # Built-in
            'yaml': 'pyyaml',
            'sqlite3': 'sqlite3',  # Built-in
            'pg': 'psycopg2-binary',
            'mysql2': 'pymysql',
            'redis': 'redis',
            'rspec': 'pytest',
            'minitest': 'pytest',
            'capybara': 'selenium',
            'pry': 'ipython',
            'rubocop': 'flake8',
            'bundler': 'pip',
        }
        
        python_requirements = []
        python_requirements.append("# Python requirements converted from Gemfile")
        python_requirements.append("# Manual review recommended")
        python_requirements.append("")
        
        for gem_name, version in gems:
            python_pkg = gem_to_python.get(gem_name, f"# {gem_name} (no Python equivalent)")
            if python_pkg and not python_pkg.startswith('#'):
                if version:
                    python_requirements.append(f"{python_pkg}{version}")
                else:
                    python_requirements.append(python_pkg)
            else:
                python_requirements.append(f"# {gem_name} - needs manual mapping")
        
        # Add common Python packages for Metasploit
        python_requirements.extend([
            "",
            "# Common Python packages for pentesting",
            "requests>=2.28.0",
            "pycryptodome>=3.15.0",
            "paramiko>=2.11.0",
            "scapy>=2.5.0",
            "impacket>=0.10.0",
            "pwntools>=4.9.0",
        ])
        
        if not self.dry_run:
            # Backup existing requirements.txt if it exists
            if requirements_txt.exists():
                backup = requirements_txt.with_suffix('.txt.backup')
                requirements_txt.rename(backup)
                logger.info(f"Backed up existing requirements.txt to {backup.name}")
            
            with open(requirements_txt, 'w') as f:
                f.write('\\n'.join(python_requirements))
            
            logger.info(f"✓ Created {requirements_txt}")
        else:
            logger.info(f"DRY RUN: Would create {requirements_txt}")
        
        self.conversions.append(("Gemfile", "requirements.txt"))
    
    def convert_ruby_version_file(self):
        """Convert .ruby-version to .python-version"""
        ruby_version = self.repo_root / ".ruby-version"
        python_version = self.repo_root / ".python-version"
        
        if not ruby_version.exists():
            logger.info("No .ruby-version found, skipping")
            return
        
        logger.info("Converting .ruby-version to .python-version...")
        
        # Simply create a .python-version file
        python_version_content = "3.11"  # Use Python 3.11 as default
        
        if not self.dry_run:
            with open(python_version, 'w') as f:
                f.write(python_version_content + '\\n')
            logger.info(f"✓ Created {python_version}")
        else:
            logger.info(f"DRY RUN: Would create {python_version}")
        
        self.conversions.append((".ruby-version", ".python-version"))
    
    def convert_rubocop_to_flake8(self):
        """Convert .rubocop.yml to Python linting config"""
        rubocop_yml = self.repo_root / ".rubocop.yml"
        
        if not rubocop_yml.exists():
            logger.info("No .rubocop.yml found, skipping")
            return
        
        logger.info("Converting .rubocop.yml to Python linting config...")
        
        # Create .flake8 config
        flake8_config = self.repo_root / ".flake8"
        flake8_content = """[flake8]
# Python linting configuration (converted from .rubocop.yml)
max-line-length = 120
exclude = 
    .git,
    __pycache__,
    build,
    dist,
    *.egg-info,
    .tox,
    venv,
    env
ignore = 
    E501,  # line too long (handled by max-line-length)
    W503,  # line break before binary operator
    E203,  # whitespace before ':'
per-file-ignores =
    __init__.py:F401
"""
        
        if not self.dry_run:
            with open(flake8_config, 'w') as f:
                f.write(flake8_content)
            logger.info(f"✓ Created {flake8_config}")
        else:
            logger.info(f"DRY RUN: Would create {flake8_config}")
        
        # Create pyproject.toml for modern Python tools
        pyproject_toml = self.repo_root / "pyproject.toml"
        if not pyproject_toml.exists():
            pyproject_content = """[tool.black]
line-length = 120
target-version = ['py311']
include = '\\.pyi?$'
extend-exclude = '''
/(
  # directories
  \\.git
  | __pycache__
  | build
  | dist
)/
'''

[tool.isort]
profile = "black"
line_length = 120

[tool.pytest.ini_options]
testpaths = ["test", "spec"]
python_files = ["test_*.py", "*_test.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = false
"""
            
            if not self.dry_run:
                with open(pyproject_toml, 'w') as f:
                    f.write(pyproject_content)
                logger.info(f"✓ Created {pyproject_toml}")
            else:
                logger.info(f"DRY RUN: Would create {pyproject_toml}")
        
        self.conversions.append((".rubocop.yml", ".flake8 + pyproject.toml"))
    
    def convert_rakefile(self):
        """Convert Rakefile to Python task management"""
        rakefile = self.repo_root / "Rakefile"
        
        if not rakefile.exists():
            logger.info("No Rakefile found, skipping")
            return
        
        logger.info("Converting Rakefile to Python task file...")
        
        # Create a Python tasks file
        tasks_py = self.repo_root / "tasks.py"
        tasks_content = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Task management for Metasploit Framework (converted from Rakefile)

Run tasks with: python3 tasks.py <task_name>
"""

import sys
import subprocess
from pathlib import Path


def task_test():
    """Run tests"""
    print("Running tests...")
    subprocess.run(["python3", "-m", "pytest", "test/"])


def task_lint():
    """Run linters"""
    print("Running linters...")
    subprocess.run(["flake8", "lib/", "modules/", "tools/"])


def task_clean():
    """Clean build artifacts"""
    print("Cleaning build artifacts...")
    import shutil
    patterns = ["__pycache__", "*.pyc", "*.pyo", "*.pyd", ".pytest_cache", "*.egg-info"]
    for pattern in patterns:
        for path in Path(".").rglob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()


def task_install():
    """Install dependencies"""
    print("Installing dependencies...")
    subprocess.run(["pip3", "install", "-r", "requirements.txt"])


def main():
    """Main task runner"""
    tasks = {
        'test': task_test,
        'lint': task_lint,
        'clean': task_clean,
        'install': task_install,
    }
    
    if len(sys.argv) < 2:
        print("Available tasks:")
        for task_name in tasks:
            print(f"  - {task_name}")
        sys.exit(0)
    
    task_name = sys.argv[1]
    if task_name in tasks:
        tasks[task_name]()
    else:
        print(f"Unknown task: {task_name}")
        sys.exit(1)


if __name__ == '__main__':
    main()
'''
        
        if not self.dry_run:
            with open(tasks_py, 'w') as f:
                f.write(tasks_content)
            tasks_py.chmod(0o755)  # Make executable
            logger.info(f"✓ Created {tasks_py}")
        else:
            logger.info(f"DRY RUN: Would create {tasks_py}")
        
        self.conversions.append(("Rakefile", "tasks.py"))
    
    def convert_config_rb_files(self):
        """Convert config/*.rb files to Python"""
        config_dir = self.repo_root / "config"
        
        if not config_dir.exists():
            logger.info("No config directory found, skipping")
            return
        
        logger.info("Converting config/*.rb files to Python...")
        
        rb_files = list(config_dir.glob("*.rb")) + list(config_dir.glob("**/*.rb"))
        
        for rb_file in rb_files:
            py_file = rb_file.with_suffix('.py')
            
            logger.info(f"  Converting {rb_file.name} -> {py_file.name}")
            
            # Read Ruby config
            with open(rb_file, 'r', encoding='utf-8', errors='ignore') as f:
                ruby_content = f.read()
            
            # Create Python equivalent
            python_content = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration file (converted from {rb_file.name})
"""

# TODO: Convert Ruby configuration to Python

# Original Ruby code (for reference):
\"\"\"
{ruby_content[:500]}
...
\"\"\"

# Python configuration
config = {{
    # TODO: Add configuration settings
}}
'''
            
            if not self.dry_run:
                with open(py_file, 'w') as f:
                    f.write(python_content)
                logger.info(f"    ✓ Created {py_file.name}")
            else:
                logger.info(f"    DRY RUN: Would create {py_file.name}")
            
            self.conversions.append((str(rb_file.relative_to(self.repo_root)), 
                                     str(py_file.relative_to(self.repo_root))))
    
    def run_all_conversions(self):
        """Run all configuration conversions"""
        logger.info("="*80)
        logger.info("RUBY CONFIG TO PYTHON CONFIG CONVERSION")
        logger.info("="*80)
        logger.info(f"Repository: {self.repo_root}")
        logger.info(f"Dry run: {self.dry_run}")
        logger.info("="*80)
        logger.info("")
        
        self.convert_gemfile_to_requirements()
        self.convert_ruby_version_file()
        self.convert_rubocop_to_flake8()
        self.convert_rakefile()
        self.convert_config_rb_files()
        
        # Print summary
        logger.info("")
        logger.info("="*80)
        logger.info("CONVERSION SUMMARY")
        logger.info("="*80)
        logger.info(f"Total conversions: {len(self.conversions)}")
        for ruby_file, python_file in self.conversions:
            logger.info(f"  {ruby_file} -> {python_file}")
        logger.info("="*80)
        
        if self.dry_run:
            logger.info("DRY RUN - No files were actually modified")
        else:
            logger.info("Config conversion completed!")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Convert Ruby config files to Python equivalents"
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    parser.add_argument(
        '--repo-root',
        type=Path,
        default=Path.cwd(),
        help='Repository root directory'
    )
    
    args = parser.parse_args()
    
    converter = ConfigConverter(
        repo_root=args.repo_root,
        dry_run=args.dry_run
    )
    
    try:
        converter.run_all_conversions()
    except Exception as e:
        logger.error(f"Conversion failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
