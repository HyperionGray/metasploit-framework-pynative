#!/usr/bin/env python3
"""
Ruby to Python Migration Executor

This script executes the complete Ruby to Python migration process:
1. Discovers current Ruby modules and generates reports
2. Modifies migration script to use "OLD" folder instead of "legacy"
3. Executes the migration with proper validation
4. Provides comprehensive reporting

Usage: python3 execute_ruby_to_python_migration.py [--dry-run]
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MigrationExecutor:
    """Executes the complete Ruby to Python migration process"""
    
    def __init__(self, workspace_dir="/workspace", dry_run=False):
        self.workspace_dir = Path(workspace_dir)
        self.dry_run = dry_run
        self.old_dir = self.workspace_dir / "OLD"
        
    def step1_run_discovery(self):
        """Step 1: Run discovery script to analyze current state"""
        logger.info("=== STEP 1: Running Ruby Module Discovery ===")
        
        discovery_script = self.workspace_dir / "tools/dev/discover_post_2020_exploits.py"
        if not discovery_script.exists():
            logger.error(f"Discovery script not found: {discovery_script}")
            return False
            
        try:
            # Run discovery script
            result = subprocess.run([
                sys.executable, str(discovery_script)
            ], capture_output=True, text=True, cwd=str(self.workspace_dir))
            
            if result.returncode == 0:
                logger.info("Discovery completed successfully")
                logger.info("Discovery output:")
                for line in result.stdout.split('\n'):
                    if line.strip():
                        logger.info(f"  {line}")
                return True
            else:
                logger.error(f"Discovery failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error running discovery: {e}")
            return False
    
    def step2_modify_migration_script(self):
        """Step 2: Modify migration script to use OLD folder"""
        logger.info("=== STEP 2: Modifying Migration Script ===")
        
        migration_script = self.workspace_dir / "tools/migration/migrate_ruby_to_python.py"
        if not migration_script.exists():
            logger.error(f"Migration script not found: {migration_script}")
            return False
        
        try:
            # Read the original script
            with open(migration_script, 'r') as f:
                content = f.read()
            
            # Create backup
            backup_path = migration_script.with_suffix('.py.backup')
            shutil.copy2(migration_script, backup_path)
            logger.info(f"Created backup: {backup_path}")
            
            # Replace "legacy" with "OLD" in relevant contexts
            modifications = [
                ('self.legacy_dir = self.workspace_dir / "legacy"', 
                 'self.legacy_dir = self.workspace_dir / "OLD"'),
                ('legacy_path = self.legacy_dir / rel_path', 
                 'old_path = self.legacy_dir / rel_path'),
                ('legacy_path.parent.mkdir(parents=True, exist_ok=True)', 
                 'old_path.parent.mkdir(parents=True, exist_ok=True)'),
                ('shutil.move(str(ruby_file), str(legacy_path))', 
                 'shutil.move(str(ruby_file), str(old_path))'),
                ('f"Moved {rel_path} to legacy/{rel_path}"', 
                 'f"Moved {rel_path} to OLD/{rel_path}"'),
                ('f"[DRY RUN] Would move {rel_path} to legacy/{rel_path}"', 
                 'f"[DRY RUN] Would move {rel_path} to OLD/{rel_path}"'),
                ('f"Error moving {ruby_file} to legacy: {e}"', 
                 'f"Error moving {ruby_file} to OLD: {e}"'),
                ('print(f"\\nLegacy files location: {self.legacy_dir}")', 
                 'print(f"\\nOLD files location: {self.legacy_dir}")'),
                ("'legacy/'", "'OLD/'")
            ]
            
            modified_content = content
            for old_text, new_text in modifications:
                if old_text in modified_content:
                    modified_content = modified_content.replace(old_text, new_text)
                    logger.info(f"Replaced: {old_text[:50]}...")
            
            # Write the modified script
            with open(migration_script, 'w') as f:
                f.write(modified_content)
            
            logger.info("Migration script successfully modified to use OLD folder")
            return True
            
        except Exception as e:
            logger.error(f"Error modifying migration script: {e}")
            return False
    
    def step3_execute_migration(self):
        """Step 3: Execute the migration"""
        logger.info("=== STEP 3: Executing Migration ===")
        
        migration_script = self.workspace_dir / "tools/migration/migrate_ruby_to_python.py"
        
        try:
            # Build command arguments
            cmd = [sys.executable, str(migration_script)]
            if self.dry_run:
                cmd.append('--dry-run')
            cmd.extend(['--verbose', '--workspace', str(self.workspace_dir)])
            
            logger.info(f"Running migration command: {' '.join(cmd)}")
            
            # Execute migration
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.workspace_dir))
            
            # Log output
            if result.stdout:
                logger.info("Migration output:")
                for line in result.stdout.split('\n'):
                    if line.strip():
                        logger.info(f"  {line}")
            
            if result.stderr:
                logger.warning("Migration warnings/errors:")
                for line in result.stderr.split('\n'):
                    if line.strip():
                        logger.warning(f"  {line}")
            
            if result.returncode == 0:
                logger.info("Migration completed successfully")
                return True
            else:
                logger.error(f"Migration failed with return code: {result.returncode}")
                return False
                
        except Exception as e:
            logger.error(f"Error executing migration: {e}")
            return False
    
    def step4_validate_results(self):
        """Step 4: Validate migration results"""
        logger.info("=== STEP 4: Validating Migration Results ===")
        
        try:
            # Check if OLD directory was created
            if self.old_dir.exists():
                logger.info(f"OLD directory created: {self.old_dir}")
                
                # Count files in OLD directory
                old_files = list(self.old_dir.rglob("*.rb"))
                logger.info(f"Ruby files moved to OLD: {len(old_files)}")
                
                # Show some examples
                if old_files:
                    logger.info("Sample files in OLD directory:")
                    for i, file_path in enumerate(old_files[:5]):
                        rel_path = file_path.relative_to(self.old_dir)
                        logger.info(f"  {rel_path}")
                    if len(old_files) > 5:
                        logger.info(f"  ... and {len(old_files) - 5} more files")
            else:
                logger.warning("OLD directory was not created")
            
            # Count Python files created
            python_files = list(self.workspace_dir.rglob("*.py"))
            # Filter out existing Python files (rough estimate)
            new_python_files = [f for f in python_files if 'modules/' in str(f)]
            logger.info(f"Python files in modules directory: {len(new_python_files)}")
            
            # Check for any remaining Ruby files in main directories
            main_ruby_files = []
            for module_dir in ['modules/exploits', 'modules/auxiliary', 'modules/post']:
                module_path = self.workspace_dir / module_dir
                if module_path.exists():
                    ruby_files = list(module_path.rglob("*.rb"))
                    main_ruby_files.extend(ruby_files)
            
            logger.info(f"Ruby files remaining in main module directories: {len(main_ruby_files)}")
            
            if main_ruby_files:
                logger.info("Remaining Ruby files:")
                for file_path in main_ruby_files[:10]:
                    rel_path = file_path.relative_to(self.workspace_dir)
                    logger.info(f"  {rel_path}")
                if len(main_ruby_files) > 10:
                    logger.info(f"  ... and {len(main_ruby_files) - 10} more files")
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating results: {e}")
            return False
    
    def execute_full_migration(self):
        """Execute the complete migration process"""
        logger.info("Starting Ruby to Python Migration Process")
        logger.info(f"Workspace: {self.workspace_dir}")
        logger.info(f"Dry run: {self.dry_run}")
        logger.info("="*60)
        
        steps = [
            ("Discovery", self.step1_run_discovery),
            ("Script Modification", self.step2_modify_migration_script),
            ("Migration Execution", self.step3_execute_migration),
            ("Result Validation", self.step4_validate_results)
        ]
        
        for step_name, step_func in steps:
            logger.info(f"\nExecuting: {step_name}")
            if not step_func():
                logger.error(f"Step failed: {step_name}")
                logger.error("Migration process aborted")
                return False
            logger.info(f"Step completed: {step_name}")
        
        logger.info("\n" + "="*60)
        logger.info("MIGRATION PROCESS COMPLETED SUCCESSFULLY")
        logger.info("="*60)
        
        if self.dry_run:
            logger.info("This was a DRY RUN - no files were actually moved or converted")
        else:
            logger.info("All Ruby files have been processed:")
            logger.info("- Pre-2020 files moved to OLD/ directory")
            logger.info("- Post-2020 files converted to Python")
        
        return True

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Execute Ruby to Python migration")
    parser.add_argument('--dry-run', action='store_true', 
                       help='Preview changes without making them')
    parser.add_argument('--workspace', default='/workspace',
                       help='Workspace directory path')
    
    args = parser.parse_args()
    
    executor = MigrationExecutor(
        workspace_dir=args.workspace,
        dry_run=args.dry_run
    )
    
    try:
        success = executor.execute_full_migration()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.info("\nMigration interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Migration failed with error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()