#!/usr/bin/env python3
"""
Systematic Ruby to Python Conversion Executor
Following the established conversion strategy to make Metasploit Python-native
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

class MetasploitPythonConverter:
    """Systematic converter following the established strategy"""
    
    def __init__(self, workspace_dir="/workspace"):
        self.workspace_dir = Path(workspace_dir)
        self.log_file = self.workspace_dir / "conversion_log.txt"
        
    def log(self, message):
        """Log message to both console and file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        print(log_message)
        
        with open(self.log_file, 'a') as f:
            f.write(log_message + "\n")
    
    def run_command(self, cmd, description):
        """Run a command and log results"""
        self.log(f"EXECUTING: {description}")
        self.log(f"Command: {cmd}")
        
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                cwd=str(self.workspace_dir)
            )
            
            if result.stdout:
                self.log(f"STDOUT: {result.stdout}")
            if result.stderr:
                self.log(f"STDERR: {result.stderr}")
            
            self.log(f"Return code: {result.returncode}")
            return result.returncode == 0, result.stdout, result.stderr
            
        except Exception as e:
            self.log(f"Error running command: {e}")
            return False, "", str(e)
    
    def execute_batch_conversion(self):
        """Execute the batch conversion using existing tools"""
        self.log("🥊 RUBY v PYTHON: ROUND 7: FIGHT! 🥊")
        self.log("Executing batch conversion to make Metasploit Python-native...")
        
        # Run the existing batch converter
        success, stdout, stderr = self.run_command(
            "python3 batch_ruby_to_python_converter.py",
            "Execute batch Ruby to Python conversion"
        )
        
        if success:
            self.log("✅ Batch conversion completed successfully")
        else:
            self.log("❌ Batch conversion encountered issues")
        
        # Get final statistics
        success, stdout, _ = self.run_command(
            "find . -name '*.rb' -type f | wc -l",
            "Count remaining Ruby files"
        )
        
        if success:
            ruby_count = int(stdout.strip())
            self.log(f"Remaining Ruby files: {ruby_count}")
        
        success, stdout, _ = self.run_command(
            "find . -name '*.py' -type f | wc -l",
            "Count total Python files"
        )
        
        if success:
            python_count = int(stdout.strip())
            self.log(f"Total Python files: {python_count}")
        
        self.log("🎉 PYTHON WINS! The republic has been restored! 🐍")

def main():
    """Main entry point"""
    converter = MetasploitPythonConverter()
    converter.execute_batch_conversion()

if __name__ == '__main__':
    main()