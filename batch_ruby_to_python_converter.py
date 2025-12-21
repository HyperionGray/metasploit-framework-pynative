#!/usr/bin/env python3
"""
Batch Ruby to Python Converter for Metasploit Framework
Converts post-2020 Ruby exploit modules to Python
"""

import os
import re
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

class BatchRubyToPythonConverter:
    """Batch converter for Ruby exploit modules to Python"""
    
    def __init__(self, workspace_dir: str = "/workspace", dry_run: bool = False):
        self.workspace_dir = Path(workspace_dir)
        self.dry_run = dry_run
        self.cutoff_date = datetime(2021, 1, 1)
        
        # Statistics
        self.stats = {
            'total_files': 0,
            'post_2020_files': 0,
            'converted_files': 0,
            'skipped_files': 0,
            'error_files': 0
        }
        
        # Ruby to Python mappings
        self.mappings = {
            'Msf::Exploit::Remote': 'RemoteExploit',
            'Msf::Exploit::Remote::HttpClient': 'HttpExploitMixin',
            'Msf::Exploit::Remote::AutoCheck': 'AutoCheckMixin',
            'MetasploitModule': 'MetasploitModule',
            'ExcellentRanking': 'ExploitRank.EXCELLENT',
            'GreatRanking': 'ExploitRank.GREAT',
            'GoodRanking': 'ExploitRank.GOOD',
            'NormalRanking': 'ExploitRank.NORMAL',
            'AverageRanking': 'ExploitRank.AVERAGE',
            'LowRanking': 'ExploitRank.LOW',
            'ManualRanking': 'ExploitRank.MANUAL',
            'nil': 'None',
            'true': 'True',
            'false': 'False',
        }
    
    def find_ruby_exploit_files(self) -> List[Path]:
        """Find all Ruby exploit files in the modules directory"""
        ruby_files = []
        
        # Focus on exploit modules
        exploits_dir = self.workspace_dir / "modules" / "exploits"
        if exploits_dir.exists():
            for ruby_file in exploits_dir.rglob("*.rb"):
                # Skip example files and already converted files
                if 'example' not in ruby_file.name.lower():
                    ruby_files.append(ruby_file)
        
        self.stats['total_files'] = len(ruby_files)
        print(f"Found {len(ruby_files)} Ruby exploit files")
        return ruby_files
    
    def get_disclosure_date(self, ruby_content: str) -> Optional[datetime]:
        """Extract disclosure date from Ruby module"""
        # Look for DisclosureDate pattern
        pattern = re.compile(r"'DisclosureDate'\s*=>\s*'([^']+)'")
        match = pattern.search(ruby_content)
        
        if match:
            date_str = match.group(1)
            try:
                return datetime.strptime(date_str, '%Y-%m-%d')
            except ValueError:
                pass
        
        return None
    
    def is_post_2020_file(self, ruby_file: Path) -> bool:
        """Check if the Ruby file is post-2020 based on disclosure date"""
        try:
            with open(ruby_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            disclosure_date = self.get_disclosure_date(content)
            if disclosure_date:
                return disclosure_date >= self.cutoff_date
            
            # Fallback to file modification time
            stat = ruby_file.stat()
            file_date = datetime.fromtimestamp(stat.st_mtime)
            return file_date >= self.cutoff_date
            
        except Exception:
            return False
    
    def convert_ruby_to_python(self, ruby_file: Path) -> str:
        """Convert a Ruby exploit file to Python"""
        
        with open(ruby_file, 'r', encoding='utf-8', errors='ignore') as f:
            ruby_content = f.read()
        
        # Extract module information
        module_info = self.extract_module_info(ruby_content)
        
        python_lines = []
        
        # Add Python header
        python_lines.extend([
            "#!/usr/bin/env python3",
            "# -*- coding: utf-8 -*-",
            '"""',
            f"{module_info.get('name', 'Converted Exploit Module')}",
            "",
            f"Converted from Ruby: {ruby_file.name}",
            "This module was automatically converted from Ruby to Python",
            "as part of the post-2020 Python migration initiative.",
            "",
            f"Original Author(s): {', '.join(module_info.get('authors', ['Unknown']))}",
            f"Disclosure Date: {module_info.get('disclosure_date', 'Unknown')}",
            '"""',
            "",
            "import sys",
            "import os",
            "import re",
            "import json",
            "import time",
            "import logging",
            "from typing import Dict, List, Optional, Any, Union",
            "",
            "# Framework imports",
            "sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../python_framework'))",
            "from core.exploit import RemoteExploit, ExploitInfo, ExploitResult, ExploitRank",
            "from helpers.http_client import HttpExploitMixin",
            "from helpers.mixins import AutoCheckMixin",
            "",
        ])
        
        # Convert the class definition and basic structure
        python_lines.extend(self.convert_class_structure(ruby_content, module_info))
        
        return '\n'.join(python_lines)
    
    def extract_module_info(self, ruby_content: str) -> Dict:
        """Extract module information from Ruby content"""
        info = {}
        
        # Extract name
        name_match = re.search(r"'Name'\s*=>\s*'([^']+)'", ruby_content)
        if name_match:
            info['name'] = name_match.group(1)
        
        # Extract authors
        authors = []
        author_pattern = re.compile(r"'Author'\s*=>\s*\[(.*?)\]", re.DOTALL)
        author_match = author_pattern.search(ruby_content)
        if author_match:
            author_content = author_match.group(1)
            # Extract individual author strings
            author_strings = re.findall(r"'([^']+)'", author_content)
            authors = author_strings
        info['authors'] = authors
        
        # Extract disclosure date
        disclosure_date = self.get_disclosure_date(ruby_content)
        if disclosure_date:
            info['disclosure_date'] = disclosure_date.strftime('%Y-%m-%d')
        
        # Extract description
        desc_match = re.search(r"'Description'\s*=>\s*%q\{(.*?)\}", ruby_content, re.DOTALL)
        if desc_match:
            info['description'] = desc_match.group(1).strip()
        
        return info
    
    def convert_class_structure(self, ruby_content: str, module_info: Dict) -> List[str]:
        """Convert the Ruby class structure to Python"""
        lines = []
        
        # Class definition
        lines.extend([
            "class MetasploitModule(RemoteExploit, HttpExploitMixin, AutoCheckMixin):",
            f'    """',
            f'    {module_info.get("name", "Converted Exploit Module")}',
            f'    ',
            f'    {module_info.get("description", "Automatically converted from Ruby")[:200]}...',
            f'    """',
            "",
        ])
        
        # Extract and convert rank
        rank_match = re.search(r'Rank\s*=\s*(\w+)', ruby_content)
        if rank_match:
            rank = rank_match.group(1)
            python_rank = self.mappings.get(rank, f'ExploitRank.{rank.upper()}')
            lines.append(f"    rank = {python_rank}")
        else:
            lines.append("    rank = ExploitRank.NORMAL")
        
        lines.append("")
        
        # Initialize method
        lines.extend([
            "    def __init__(self):",
            "        info = ExploitInfo(",
            f'            name="{module_info.get("name", "Converted Exploit")}",',
            f'            description="""{module_info.get("description", "Converted from Ruby")}""",',
            f'            author={module_info.get("authors", ["Unknown"])},',
            f'            disclosure_date="{module_info.get("disclosure_date", "Unknown")}",',
            "            rank=self.rank",
            "        )",
            "        super().__init__(info)",
            "        ",
            "        # TODO: Convert register_options from Ruby",
            "        # TODO: Convert targets from Ruby",
            "        # TODO: Convert other initialization from Ruby",
            "",
        ])
        
        # Add placeholder methods
        methods = ['check', 'exploit']
        for method in methods:
            lines.extend([
                f"    def {method}(self) -> ExploitResult:",
                f'        """TODO: Implement {method} method from Ruby version"""',
                "        # TODO: Convert Ruby implementation",
                "        return ExploitResult(False, f'{method} not yet implemented')",
                "",
            ])
        
        # Add main execution block
        lines.extend([
            "",
            "if __name__ == '__main__':",
            "    # Standalone execution for testing",
            "    import argparse",
            "    ",
            "    parser = argparse.ArgumentParser(description='Run exploit module')",
            "    parser.add_argument('--host', required=True, help='Target host')",
            "    parser.add_argument('--port', type=int, default=80, help='Target port')",
            "    parser.add_argument('--check-only', action='store_true', help='Only run check')",
            "    parser.add_argument('--verbose', action='store_true', help='Verbose output')",
            "    ",
            "    args = parser.parse_args()",
            "    ",
            "    # TODO: Implement standalone execution",
            "    print('Standalone execution not yet implemented')",
        ])
        
        return lines
    
    def convert_file(self, ruby_file: Path) -> bool:
        """Convert a single Ruby file to Python"""
        try:
            print(f"Converting: {ruby_file.relative_to(self.workspace_dir)}")
            
            # Generate Python content
            python_content = self.convert_ruby_to_python(ruby_file)
            
            # Determine output path
            python_file = ruby_file.with_suffix('.py')
            
            if not self.dry_run:
                # Write Python file
                with open(python_file, 'w', encoding='utf-8') as f:
                    f.write(python_content)
                
                # Make executable if original was executable
                if os.access(ruby_file, os.X_OK):
                    os.chmod(python_file, 0o755)
            
            print(f"  ✓ Converted to: {python_file.name}")
            return True
            
        except Exception as e:
            print(f"  ✗ Error converting {ruby_file.name}: {e}")
            return False
    
    def run_batch_conversion(self):
        """Run the batch conversion process"""
        print("Starting batch Ruby to Python conversion...")
        print(f"Workspace: {self.workspace_dir}")
        print(f"Dry run: {self.dry_run}")
        print(f"Cutoff date: {self.cutoff_date}")
        print("-" * 60)
        
        # Find Ruby files
        ruby_files = self.find_ruby_exploit_files()
        
        # Process each file
        for ruby_file in ruby_files:
            # Check if it's post-2020
            if self.is_post_2020_file(ruby_file):
                self.stats['post_2020_files'] += 1
                
                # Check if Python version already exists
                python_file = ruby_file.with_suffix('.py')
                if python_file.exists():
                    print(f"Skipping (Python version exists): {ruby_file.relative_to(self.workspace_dir)}")
                    self.stats['skipped_files'] += 1
                    continue
                
                # Convert the file
                if self.convert_file(ruby_file):
                    self.stats['converted_files'] += 1
                else:
                    self.stats['error_files'] += 1
            else:
                print(f"Skipping (pre-2021): {ruby_file.relative_to(self.workspace_dir)}")
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print conversion summary"""
        print("\n" + "="*60)
        print("BATCH CONVERSION SUMMARY")
        print("="*60)
        print(f"Total Ruby files found:     {self.stats['total_files']}")
        print(f"Post-2020 files identified: {self.stats['post_2020_files']}")
        print(f"Files converted:            {self.stats['converted_files']}")
        print(f"Files skipped:              {self.stats['skipped_files']}")
        print(f"Conversion errors:          {self.stats['error_files']}")
        print("="*60)
        
        if self.dry_run:
            print("DRY RUN - No files were actually converted")
        else:
            print("Conversion completed!")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Batch convert Ruby exploits to Python")
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    parser.add_argument('--workspace', default='/workspace', help='Workspace directory path')
    
    args = parser.parse_args()
    
    converter = BatchRubyToPythonConverter(
        workspace_dir=args.workspace,
        dry_run=args.dry_run
    )
    
    try:
        converter.run_batch_conversion()
    except KeyboardInterrupt:
        print("\nConversion interrupted by user")
    except Exception as e:
        print(f"Conversion failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()