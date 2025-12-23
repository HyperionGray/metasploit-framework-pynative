#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Batch Ruby to Python Converter

Converts all remaining Ruby files (with #!/usr/bin/env ruby shebang) to Python.
This script handles various types of files including executables, utilities, 
and helper scripts.
"""

import os
import sys
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)


class Ruby2PyBatchConverter:
    """Batch convert Ruby files to Python."""
    
    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root)
        self.ast_transpiler = self.repo_root / "tools" / "ast_transpiler" / "ast_translator.py"
        self.ruby_converter = self.repo_root / "tools" / "ruby_to_python_converter.py"
        self.converted_files = []
        self.failed_files = []
        
    def find_ruby_files(self) -> List[Path]:
        """Find all files with Ruby shebang."""
        ruby_files = []
        
        # Known file list from issue
        file_list = [
            "./data/exploits/capture/http/forms/extractforms.rb",
            "./data/exploits/capture/http/forms/grabforms.rb",
            "./data/sounds/aiff2wav.rb",
            "./external/source/DLLHijackAuditKit/regenerate_binaries.rb",
            "./external/source/cmdstager/debug_asm/fix_up.rb",
            "./external/source/exploits/CVE-2016-4655/create_bin.rb",
            "./external/source/exploits/CVE-2017-13861/create_bin.rb",
            "./external/source/exploits/CVE-2018-4404/gen_offsets.rb",
            "./external/source/exploits/cve-2010-4452/get_offsets.rb",
            "./external/source/osx/x86/src/test/write_size_and_data.rb",
            "./external/source/unixasm/aix-power.rb",
            "./external/source/unixasm/objdumptoc.rb",
            "./lib/rex/google/geolocation.rb",
            "./modules/legacy/auxiliary/dos/smb/smb_loris.rb",
            "./modules/legacy/exploits/windows/ftp/vermillion_ftpd_port.rb",
            "./msfconsole",
            "./msfd",
            "./msfdb",
            "./msfrpc",
            "./msfrpcd",
            "./msfupdate",
            "./msfvenom",
            "./script/rails",
            "./spec/lib/msf/core/modules/loader/executable_spec.rb",
            "./tools/dev/add_pr_fetch.rb",
            "./tools/dev/check_external_scripts.rb",
            "./tools/dev/find_release_notes.rb",
            "./tools/dev/generate_mitre_attack_technique_constants.rb",
            "./tools/dev/hash_cracker_validator.rb",
            "./tools/dev/msfdb_ws",
            "./tools/dev/msftidy.rb",
            "./tools/dev/msftidy_docs.rb",
            "./tools/dev/pre-commit-hook.rb",
            "./tools/dev/set_binary_encoding.rb",
            "./tools/dev/update_joomla_components.rb",
            "./tools/dev/update_user_agent_strings.rb",
            "./tools/dev/update_wordpress_vulnerabilities.rb",
            "./tools/exploit/egghunter.rb",
            "./tools/exploit/exe2vba.rb",
            "./tools/exploit/exe2vbs.rb",
            "./tools/exploit/find_badchars.rb",
            "./tools/exploit/java_deserializer.rb",
            "./tools/exploit/jsobfu.rb",
            "./tools/exploit/metasm_shell.rb",
            "./tools/exploit/msf_irb_shell.rb",
            "./tools/exploit/msu_finder.rb",
            "./tools/exploit/nasm_shell.rb",
            "./tools/exploit/pattern_create.rb",
            "./tools/exploit/pattern_offset.rb",
            "./tools/exploit/pdf2xdp.rb",
            "./tools/exploit/psexec.rb",
            "./tools/exploit/random_compile_c.rb",
            "./tools/exploit/reg.rb",
            "./tools/exploit/virustotal.rb",
            "./tools/hardware/elm327_relay.rb",
            "./tools/modules/committer_count.rb",
            "./tools/modules/cve_xref.rb",
            "./tools/modules/file_pull_requests.rb",
            "./tools/modules/generate_mettle_payloads.rb",
            "./tools/modules/missing_payload_tests.rb",
            "./tools/modules/module_author.rb",
            "./tools/modules/module_commits.rb",
            "./tools/modules/module_count.rb",
            "./tools/modules/module_description.rb",
            "./tools/modules/module_disclodate.rb",
            "./tools/modules/module_license.rb",
            "./tools/modules/module_missing_reference.rb",
            "./tools/modules/module_mixins.rb",
            "./tools/modules/module_payloads.rb",
            "./tools/modules/module_ports.rb",
            "./tools/modules/module_rank.rb",
            "./tools/modules/module_reference.rb",
            "./tools/modules/module_targets.rb",
            "./tools/modules/payload_lengths.rb",
            "./tools/modules/solo.rb",
            "./tools/modules/update_payload_cached_sizes.rb",
            "./tools/modules/verify_datastore.rb",
            "./tools/password/cpassword_decrypt.rb",
            "./tools/password/vxdigger.rb",
            "./tools/password/vxencrypt.rb",
            "./tools/password/winscp_decrypt.rb",
            "./tools/password/md5_lookup.rb",
            "./tools/payloads/ysoserial/dot_net.rb",
            "./tools/payloads/ysoserial/find_ysoserial_offsets.rb",
            "./tools/recon/google_geolocate_bssid.rb",
            "./tools/recon/makeiplist.rb",
            "./tools/smb_file_server.rb",
            "./tools/ast_transpiler/ruby_ast_extractor.rb",
            "./validate_module.rb",
            "./check_md5_lookup.rb",
            "./debug_load.rb",
            "./simple_test.rb",
            "./syntax_test.rb",
            "./test_framework_load.rb",
            "./test_like_spec.rb",
            "./test_md5_load.rb",
            "./test_md5_lookup.rb",
            "./test_ruby_syntax.rb",
            "./test_ruby_wrapper.rb",
        ]
        
        for file_path in file_list:
            full_path = self.repo_root / file_path.lstrip('./')
            if full_path.exists():
                # Check if it has Ruby shebang
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        first_line = f.readline()
                        if 'ruby' in first_line.lower():
                            ruby_files.append(full_path)
                except Exception as e:
                    logger.warning(f"Could not read {full_path}: {e}")
        
        return ruby_files
    
    def convert_simple_script(self, ruby_file: Path) -> Tuple[bool, str]:
        """
        Convert a simple Ruby script to Python using pattern-based approach.
        
        Args:
            ruby_file: Path to Ruby file
            
        Returns:
            Tuple of (success, python_code)
        """
        try:
            with open(ruby_file, 'r', encoding='utf-8', errors='ignore') as f:
                ruby_content = f.read()
            
            python_content = self._translate_ruby_to_python(ruby_content, ruby_file)
            return True, python_content
            
        except Exception as e:
            logger.error(f"Failed to convert {ruby_file}: {e}")
            return False, ""
    
    def _translate_ruby_to_python(self, ruby_code: str, source_file: Path) -> str:
        """Translate Ruby code to Python using pattern matching."""
        
        # Start with Python shebang
        lines = ruby_code.split('\n')
        python_lines = ['#!/usr/bin/env python3', '# -*- coding: utf-8 -*-']
        
        # Add comment about conversion
        python_lines.append('')
        python_lines.append(f'"""')
        python_lines.append(f'Converted from Ruby: {source_file.name}')
        python_lines.append(f'')
        python_lines.append(f'This file was automatically converted from Ruby to Python.')
        python_lines.append(f'Manual review and testing may be required.')
        python_lines.append(f'"""')
        python_lines.append('')
        
        # Add common imports
        python_lines.append('import sys')
        python_lines.append('import os')
        python_lines.append('import re')
        python_lines.append('import subprocess')
        python_lines.append('from pathlib import Path')
        python_lines.append('')
        
        # Skip shebang and encoding lines
        code_start = 0
        for i, line in enumerate(lines):
            if line.startswith('#!') or 'coding' in line or line.strip() == '':
                code_start = i + 1
            else:
                break
        
        # Process each line
        in_multiline_comment = False
        indent_level = 0
        
        for line in lines[code_start:]:
            # Handle comments
            stripped = line.strip()
            
            if not stripped or stripped.startswith('#'):
                # Keep comments as-is
                python_lines.append(line)
                continue
            
            # Basic Ruby to Python translations
            py_line = line
            
            # Class definitions
            py_line = re.sub(r'class\s+(\w+)\s*<\s*([\w:]+)', r'class \1(\2):', py_line)
            py_line = re.sub(r'class\s+(\w+)\s*$', r'class \1:', py_line)
            
            # Method definitions
            py_line = re.sub(r'def\s+(\w+)\s*\(([^)]*)\)', r'def \1(self, \2):', py_line)
            py_line = re.sub(r'def\s+(\w+)\s*$', r'def \1(self):', py_line)
            py_line = re.sub(r'def\s+self\.(\w+)', r'@staticmethod\n    def \1', py_line)
            
            # Instance variables
            py_line = re.sub(r'@(\w+)', r'self.\1', py_line)
            
            # Keywords
            py_line = re.sub(r'\btrue\b', 'True', py_line)
            py_line = re.sub(r'\bfalse\b', 'False', py_line)
            py_line = re.sub(r'\bnil\b', 'None', py_line)
            py_line = re.sub(r'\bunless\b', 'if not', py_line)
            py_line = re.sub(r'\belsif\b', 'elif', py_line)
            
            # Hash/Dict syntax
            py_line = re.sub(r'=>', ':', py_line)
            py_line = re.sub(r':(\w+)', r'"\1"', py_line)  # :symbol -> "symbol"
            
            # puts/print
            py_line = re.sub(r'puts\s+', 'print(', py_line)
            if 'print(' in py_line and not py_line.rstrip().endswith(')'):
                py_line = py_line.rstrip() + ')'
            
            # String interpolation (basic)
            py_line = re.sub(r'#\{([^}]+)\}', r'{\1}', py_line)
            if '{' in py_line and '"' in py_line:
                py_line = py_line.replace('"', 'f"', 1)
            
            # Block syntax (simple)
            py_line = re.sub(r'\.each\s+do\s+\|([^|]+)\|', r'for \1 in ', py_line)
            py_line = re.sub(r'\bend\s*$', '', py_line)  # Remove 'end'
            
            # require -> import
            if 'require' in py_line:
                match = re.search(r"require\s+['\"]([^'\"]+)['\"]", py_line)
                if match:
                    module = match.group(1)
                    # Skip if already in imports section
                    if 'import' not in py_line:
                        py_line = f"# TODO: import {module.replace('/', '.')}"
            
            python_lines.append(py_line)
        
        # Add main execution block if needed
        python_lines.append('')
        python_lines.append('if __name__ == "__main__":')
        python_lines.append('    # TODO: Add main execution logic')
        python_lines.append('    pass')
        
        return '\n'.join(python_lines)
    
    def convert_file(self, ruby_file: Path) -> bool:
        """
        Convert a Ruby file to Python.
        
        Args:
            ruby_file: Path to Ruby file to convert
            
        Returns:
            True if conversion successful
        """
        logger.info(f"Converting: {ruby_file.relative_to(self.repo_root)}")
        
        # Determine output path
        if ruby_file.suffix == '.rb':
            python_file = ruby_file.with_suffix('.py')
        else:
            # For files without extension (like msfconsole), keep name and add .py
            python_file = ruby_file.parent / f"{ruby_file.name}.py"
        
        # Check if Python version already exists
        if python_file.exists():
            logger.info(f"  Python version already exists: {python_file.name}")
            return True
        
        # Try AST-based transpiler first for .rb files
        if ruby_file.suffix == '.rb' and self.ast_transpiler.exists():
            try:
                result = subprocess.run(
                    [sys.executable, str(self.ast_transpiler), str(ruby_file), 
                     '-o', str(python_file)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0 and python_file.exists():
                    logger.info(f"  ✓ Converted with AST transpiler: {python_file.name}")
                    self.converted_files.append((ruby_file, python_file))
                    return True
            except Exception as e:
                logger.warning(f"  AST transpiler failed: {e}")
        
        # Fall back to pattern-based conversion
        success, python_code = self.convert_simple_script(ruby_file)
        
        if success and python_code:
            try:
                with open(python_file, 'w', encoding='utf-8') as f:
                    f.write(python_code)
                
                # Make executable if original was executable
                if os.access(ruby_file, os.X_OK):
                    os.chmod(python_file, 0o755)
                
                logger.info(f"  ✓ Converted with pattern matching: {python_file.name}")
                self.converted_files.append((ruby_file, python_file))
                return True
            except Exception as e:
                logger.error(f"  ✗ Failed to write {python_file}: {e}")
                self.failed_files.append((ruby_file, str(e)))
                return False
        else:
            logger.error(f"  ✗ Conversion failed for {ruby_file.name}")
            self.failed_files.append((ruby_file, "Conversion produced no output"))
            return False
    
    def convert_all(self) -> Dict[str, int]:
        """
        Convert all Ruby files to Python.
        
        Returns:
            Dictionary with conversion statistics
        """
        ruby_files = self.find_ruby_files()
        
        logger.info(f"Found {len(ruby_files)} Ruby files to convert")
        logger.info("="*70)
        
        for ruby_file in ruby_files:
            self.convert_file(ruby_file)
        
        logger.info("="*70)
        logger.info(f"Conversion complete!")
        logger.info(f"  Successful: {len(self.converted_files)}")
        logger.info(f"  Failed: {len(self.failed_files)}")
        
        if self.failed_files:
            logger.info("\nFailed files:")
            for ruby_file, error in self.failed_files:
                logger.info(f"  - {ruby_file.name}: {error}")
        
        return {
            'total': len(ruby_files),
            'converted': len(self.converted_files),
            'failed': len(self.failed_files)
        }


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Batch convert Ruby files to Python'
    )
    parser.add_argument(
        '--repo-root',
        type=str,
        default='.',
        help='Root directory of the repository'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    repo_root = Path(args.repo_root).resolve()
    
    if not repo_root.exists():
        logger.error(f"Repository root not found: {repo_root}")
        sys.exit(1)
    
    converter = Ruby2PyBatchConverter(repo_root)
    stats = converter.convert_all()
    
    # Exit with error if any conversions failed
    if stats['failed'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
