#!/usr/bin/env python3
"""
Run discovery for Ruby files that need migration
"""

import os
import re
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

class RubyFileDiscovery:
    """Discover Ruby files for migration"""
    
    def __init__(self, workspace_dir: str = "/workspace"):
        self.workspace_dir = Path(workspace_dir)
        self.cutoff_date = datetime(2021, 1, 1)
    
    def find_ruby_files(self) -> List[Path]:
        """Find all Ruby files in relevant directories"""
        ruby_files = []
        
        # Target directories
        target_dirs = [
            "modules/exploits",
            "modules/auxiliary", 
            "modules/post",
            "lib/msf",
            "lib/rex"
        ]
        
        for target_dir in target_dirs:
            full_path = self.workspace_dir / target_dir
            if full_path.exists():
                ruby_files.extend(full_path.rglob("*.rb"))
        
        return ruby_files
    
    def analyze_file(self, ruby_file: Path) -> Dict:
        """Analyze a Ruby file for migration classification"""
        try:
            with open(ruby_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract metadata
            info = {
                'file': ruby_file.relative_to(self.workspace_dir),
                'size': len(content),
                'lines': len(content.split('\n')),
                'disclosure_date': None,
                'name': None,
                'classification': 'unknown'
            }
            
            # Look for disclosure date
            date_match = re.search(r"'DisclosureDate'\s*=>\s*'([^']+)'", content)
            if date_match:
                date_str = date_match.group(1)
                info['disclosure_date'] = date_str
                try:
                    disclosure_date = datetime.strptime(date_str, '%Y-%m-%d')
                    if disclosure_date >= self.cutoff_date:
                        info['classification'] = 'post_2020'
                    else:
                        info['classification'] = 'pre_2020'
                except ValueError:
                    info['classification'] = 'invalid_date'
            
            # Look for module name
            name_match = re.search(r"'Name'\s*=>\s*'([^']+)'", content)
            if name_match:
                info['name'] = name_match.group(1)
            
            return info
            
        except Exception as e:
            return {
                'file': ruby_file.relative_to(self.workspace_dir),
                'error': str(e),
                'classification': 'error'
            }
    
    def run_discovery(self) -> Dict:
        """Run complete discovery process"""
        print("Starting Ruby file discovery...")
        
        ruby_files = self.find_ruby_files()
        print(f"Found {len(ruby_files)} Ruby files to analyze")
        
        results = {
            'total_files': len(ruby_files),
            'post_2020': [],
            'pre_2020': [],
            'unknown': [],
            'errors': []
        }
        
        for ruby_file in ruby_files:
            info = self.analyze_file(ruby_file)
            classification = info.get('classification', 'unknown')
            
            if classification == 'post_2020':
                results['post_2020'].append(info)
            elif classification == 'pre_2020':
                results['pre_2020'].append(info)
            elif classification == 'error':
                results['errors'].append(info)
            else:
                results['unknown'].append(info)
        
        return results
    
    def print_summary(self, results: Dict):
        """Print discovery summary"""
        print("\n" + "="*60)
        print("RUBY FILE DISCOVERY SUMMARY")
        print("="*60)
        print(f"Total files analyzed:     {results['total_files']}")
        print(f"Post-2020 files:          {len(results['post_2020'])}")
        print(f"Pre-2020 files:           {len(results['pre_2020'])}")
        print(f"Unknown classification:   {len(results['unknown'])}")
        print(f"Analysis errors:          {len(results['errors'])}")
        print("="*60)
        
        if results['post_2020']:
            print("\nPost-2020 files (candidates for Python conversion):")
            for info in results['post_2020'][:10]:  # Show first 10
                print(f"  {info['disclosure_date']}: {info['file']}")
            if len(results['post_2020']) > 10:
                print(f"  ... and {len(results['post_2020']) - 10} more")

def main():
    """Main entry point"""
    discovery = RubyFileDiscovery()
    results = discovery.run_discovery()
    discovery.print_summary(results)

if __name__ == '__main__':
    main()