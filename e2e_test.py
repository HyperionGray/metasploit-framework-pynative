#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
End-to-End Test Script for Metasploit Framework PyNative

This script performs a comprehensive E2E test of the installation and basic
operation of metasploit-framework-pynative as requested.

Test Plan:
1. Environment setup and dependency installation
2. Basic tool functionality (help, version, basic commands)
3. Smoke tests for msfconsole.py and msfvenom
4. Documentation of results and any issues found
"""

import subprocess
import sys
import os
import tempfile
import shutil
from pathlib import Path
import time


class E2ETestRunner:
    """End-to-End test runner for MSF PyNative"""
    
    def __init__(self):
        self.test_results = []
        self.errors = []
        self.start_time = time.time()
        
    def log_result(self, test_name, success, output="", error=""):
        """Log test result"""
        result = {
            'test': test_name,
            'success': success,
            'output': output,
            'error': error,
            'timestamp': time.time() - self.start_time
        }
        self.test_results.append(result)
        
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if output and success:
            print(f"   Output: {output[:100]}{'...' if len(output) > 100 else ''}")
        if error:
            print(f"   Error: {error}")
        print()
        
    def run_command(self, cmd, cwd=None, timeout=30):
        """Run a command and capture output"""
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                cwd=cwd
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, "", str(e)
            
    def test_python_version(self):
        """Test Python version compatibility"""
        success, output, error = self.run_command("python3 --version")
        if success:
            version_info = output.strip()
            # Check if Python 3.8+
            version_parts = version_info.split()[1].split('.')
            major, minor = int(version_parts[0]), int(version_parts[1])
            if major >= 3 and minor >= 8:
                self.log_result("Python Version Check", True, version_info)
            else:
                self.log_result("Python Version Check", False, version_info, "Python 3.8+ required")
        else:
            self.log_result("Python Version Check", False, output, error)
            
    def test_venv_creation(self):
        """Test virtual environment creation"""
        success, output, error = self.run_command("python3 -m venv test_venv")
        self.log_result("Virtual Environment Creation", success, output, error)
        return success
        
    def test_dependency_installation(self):
        """Test installation of requirements.txt"""
        # First, let's try to install just the essential dependencies to avoid timeout
        essential_deps = [
            "requests>=2.28.0",
            "pyyaml>=6.0",
            "click>=8.1.0",
            "rich>=12.5.0",
            "pytest>=7.0.0"
        ]
        
        # Create a minimal requirements file for testing
        with open("requirements_minimal.txt", "w") as f:
            f.write("\n".join(essential_deps))
            
        success, output, error = self.run_command(
            "test_venv/bin/python -m pip install -r requirements_minimal.txt",
            timeout=120
        )
        
        if success:
            self.log_result("Essential Dependencies Installation", True, "Essential packages installed successfully")
        else:
            self.log_result("Essential Dependencies Installation", False, output, error)
            
        # Try to install full requirements (but don't fail the test if it times out)
        print("Attempting full requirements.txt installation (may take several minutes)...")
        full_success, full_output, full_error = self.run_command(
            "test_venv/bin/python -m pip install -r requirements.txt",
            timeout=300  # 5 minutes
        )
        
        if full_success:
            self.log_result("Full Requirements Installation", True, "All packages installed successfully")
        else:
            self.log_result("Full Requirements Installation", False, 
                          "Installation incomplete (timeout or errors)", full_error)
            
        return success  # Return success of essential deps
        
    def test_msfconsole_help(self):
        """Test msfconsole.py help functionality"""
        success, output, error = self.run_command("python3 msfconsole.py -h")
        if success and "Metasploit Framework Console" in output:
            self.log_result("msfconsole.py Help", True, "Help displayed correctly")
        else:
            self.log_result("msfconsole.py Help", False, output, error)
        return success
        
    def test_msfconsole_version(self):
        """Test msfconsole.py version command"""
        success, output, error = self.run_command("python3 msfconsole.py -v")
        if success and "Framework:" in output and "PyNative" in output:
            self.log_result("msfconsole.py Version", True, output.strip())
        else:
            self.log_result("msfconsole.py Version", False, output, error)
        return success
        
    def test_msfconsole_execute_command(self):
        """Test msfconsole.py command execution"""
        success, output, error = self.run_command('python3 msfconsole.py -q -x "version; exit"')
        if success and "Framework:" in output:
            self.log_result("msfconsole.py Execute Command", True, "Version command executed successfully")
        else:
            self.log_result("msfconsole.py Execute Command", False, output, error)
        return success
        
    def test_msfvenom_help(self):
        """Test msfvenom help functionality"""
        success, output, error = self.run_command("python3 msfvenom -h")
        if success and "MsfVenom" in output and "payload generator" in output:
            self.log_result("msfvenom Help", True, "Help displayed correctly")
        else:
            self.log_result("msfvenom Help", False, output, error)
        return success
        
    def test_msfvenom_list_payloads(self):
        """Test msfvenom payload listing"""
        success, output, error = self.run_command("python3 msfvenom -l payloads")
        if success and "Framework Payloads" in output:
            self.log_result("msfvenom List Payloads", True, "Payloads listed successfully")
        else:
            self.log_result("msfvenom List Payloads", False, output, error)
        return success
        
    def test_msfvenom_list_formats(self):
        """Test msfvenom format listing"""
        success, output, error = self.run_command("python3 msfvenom -l formats")
        if success and "Framework" in output and "Formats" in output:
            self.log_result("msfvenom List Formats", True, "Formats listed successfully")
        else:
            self.log_result("msfvenom List Formats", False, output, error)
        return success
        
    def test_msfvenom_payload_generation(self):
        """Test basic payload generation"""
        success, output, error = self.run_command(
            "python3 msfvenom -p generic/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444"
        )
        if success and ("payload" in output.lower() or "print" in output):
            self.log_result("msfvenom Payload Generation", True, "Payload generated successfully")
        else:
            self.log_result("msfvenom Payload Generation", False, output, error)
        return success
        
    def cleanup(self):
        """Clean up test artifacts"""
        try:
            if os.path.exists("test_venv"):
                shutil.rmtree("test_venv")
            if os.path.exists("requirements_minimal.txt"):
                os.remove("requirements_minimal.txt")
        except Exception as e:
            print(f"Cleanup warning: {e}")
            
    def generate_report(self):
        """Generate final test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        print("=" * 80)
        print("E2E TEST REPORT - METASPLOIT FRAMEWORK PYNATIVE")
        print("=" * 80)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        print(f"Total Runtime: {time.time() - self.start_time:.2f} seconds")
        print()
        
        if failed_tests > 0:
            print("FAILED TESTS:")
            print("-" * 40)
            for result in self.test_results:
                if not result['success']:
                    print(f"❌ {result['test']}")
                    if result['error']:
                        print(f"   Error: {result['error']}")
            print()
            
        print("DETAILED RESULTS:")
        print("-" * 40)
        for result in self.test_results:
            status = "✅" if result['success'] else "❌"
            print(f"{status} {result['test']} ({result['timestamp']:.2f}s)")
            
        print()
        print("FOLLOW-UP ITEMS:")
        print("-" * 40)
        
        follow_ups = []
        
        # Check for specific issues
        for result in self.test_results:
            if not result['success']:
                if "Dependencies" in result['test']:
                    follow_ups.append("• Review requirements.txt for problematic packages")
                    follow_ups.append("• Consider creating requirements-minimal.txt for basic functionality")
                elif "msfconsole" in result['test']:
                    follow_ups.append("• Debug msfconsole.py argument parsing or command execution")
                elif "msfvenom" in result['test']:
                    follow_ups.append("• Debug msfvenom functionality or payload generation")
                    
        if not follow_ups:
            follow_ups.append("• All tests passed! Consider adding more comprehensive tests")
            follow_ups.append("• Test with actual exploit modules when framework is more complete")
            follow_ups.append("• Add integration tests with database functionality")
            
        for item in set(follow_ups):  # Remove duplicates
            print(item)
            
        print()
        print("INSTALLATION SUMMARY:")
        print("-" * 40)
        print("1. Clone repository: git clone <repo-url>")
        print("2. Create virtual environment: python3 -m venv venv")
        print("3. Activate environment: source venv/bin/activate")
        print("4. Install dependencies: pip install -r requirements.txt")
        print("5. Test basic functionality:")
        print("   - python3 msfconsole.py -h")
        print("   - python3 msfconsole.py -q -x 'version; exit'")
        print("   - python3 msfvenom -h")
        print("   - python3 msfvenom -l payloads")
        
        return passed_tests == total_tests
        
    def run_all_tests(self):
        """Run all E2E tests"""
        print("Starting E2E Tests for Metasploit Framework PyNative")
        print("=" * 60)
        print()
        
        # Environment tests
        self.test_python_version()
        
        # Installation tests
        venv_success = self.test_venv_creation()
        if venv_success:
            self.test_dependency_installation()
        
        # Functionality tests
        self.test_msfconsole_help()
        self.test_msfconsole_version()
        self.test_msfconsole_execute_command()
        
        self.test_msfvenom_help()
        self.test_msfvenom_list_payloads()
        self.test_msfvenom_list_formats()
        self.test_msfvenom_payload_generation()
        
        # Generate final report
        success = self.generate_report()
        
        # Cleanup
        self.cleanup()
        
        return success


def main():
    """Main entry point"""
    print("Metasploit Framework PyNative - E2E Test Suite")
    print("=" * 50)
    print()
    
    # Check if we're in the right directory
    if not os.path.exists("msfconsole.py") or not os.path.exists("msfvenom"):
        print("❌ Error: Please run this script from the metasploit-framework-pynative root directory")
        print("   Expected files: msfconsole.py, msfvenom, requirements.txt")
        return 1
        
    runner = E2ETestRunner()
    success = runner.run_all_tests()
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())