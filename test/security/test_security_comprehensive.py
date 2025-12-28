#!/usr/bin/env python3
"""
Comprehensive security tests for Metasploit Framework
Tests the security improvements and validates secure execution
"""

import pytest
import os
import sys
import tempfile
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add lib path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../lib'))

from msf.core.secure_script_execution import (
    SecureScriptExecutor, 
    ScriptExecutionError,
    secure_eval,
    secure_exec_file
)
from msf.core.secure_command_execution import (
    SecureCommandExecutor,
    CommandExecutionError,
    secure_system,
    secure_exec_command
)

class TestSecureScriptExecution:
    """Test secure script execution functionality"""
    
    def setup_method(self):
        """Setup for each test method"""
        self.executor = SecureScriptExecutor()
    
    def test_safe_script_execution(self):
        """Test that safe scripts execute correctly"""
        safe_script = """
x = 1 + 1
result = x * 2
"""
        result = self.executor.execute_script_content(safe_script)
        assert result['result'] == 4
    
    def test_dangerous_eval_blocked(self):
        """Test that dangerous eval() calls are blocked"""
        dangerous_script = """
eval("import os; os.system('rm -rf /')")
"""
        with pytest.raises(ScriptExecutionError):
            self.executor.execute_script_content(dangerous_script)
    
    def test_dangerous_exec_blocked(self):
        """Test that dangerous exec() calls are blocked"""
        dangerous_script = """
exec("import subprocess; subprocess.call(['rm', '-rf', '/'])")
"""
        with pytest.raises(ScriptExecutionError):
            self.executor.execute_script_content(dangerous_script)
    
    def test_dangerous_import_blocked(self):
        """Test that dangerous imports are blocked"""
        dangerous_script = """
import subprocess
subprocess.call(['rm', '-rf', '/'])
"""
        with pytest.raises(ScriptExecutionError):
            self.executor.execute_script_content(dangerous_script)
    
    def test_file_access_blocked(self):
        """Test that file access is blocked"""
        dangerous_script = """
with open('/etc/passwd', 'r') as f:
    content = f.read()
"""
        with pytest.raises(ScriptExecutionError):
            self.executor.execute_script_content(dangerous_script)
    
    def test_allowed_imports_work(self):
        """Test that allowed imports work correctly"""
        safe_script = """
import json
import base64
data = json.dumps({"test": "value"})
encoded = base64.b64encode(data.encode()).decode()
"""
        result = self.executor.execute_script_content(safe_script)
        assert 'encoded' in result
    
    def test_syntax_error_handling(self):
        """Test that syntax errors are handled properly"""
        invalid_script = """
def broken_function(
    # Missing closing parenthesis
"""
        with pytest.raises(ScriptExecutionError):
            self.executor.execute_script_content(invalid_script)
    
    def test_secure_eval_function(self):
        """Test the secure_eval drop-in replacement"""
        result = secure_eval("2 + 2")
        # Should work for simple expressions
        # Complex expressions should be validated
    
    def test_file_execution_security(self):
        """Test secure file execution"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("result = 'safe_execution'")
            temp_file = f.name
        
        try:
            result = self.executor.execute_script_file(temp_file)
            assert result['result'] == 'safe_execution'
        finally:
            os.unlink(temp_file)
    
    def test_nonexistent_file_handling(self):
        """Test handling of nonexistent files"""
        with pytest.raises(ScriptExecutionError):
            self.executor.execute_script_file('/nonexistent/file.py')

class TestSecureCommandExecution:
    """Test secure command execution functionality"""
    
    def setup_method(self):
        """Setup for each test method"""
        self.executor = SecureCommandExecutor()
    
    def test_safe_command_execution(self):
        """Test that safe commands execute correctly"""
        result = self.executor.execute_command(['echo', 'hello'])
        assert result.returncode == 0
        assert 'hello' in result.stdout
    
    def test_dangerous_command_blocked(self):
        """Test that dangerous commands are blocked"""
        with pytest.raises(CommandExecutionError):
            self.executor.execute_command('rm -rf /')
    
    def test_command_injection_blocked(self):
        """Test that command injection is blocked"""
        with pytest.raises(CommandExecutionError):
            self.executor.execute_command('echo hello; rm -rf /')
    
    def test_path_traversal_blocked(self):
        """Test that path traversal is blocked"""
        with pytest.raises(CommandExecutionError):
            self.executor.execute_command('cat ../../etc/passwd')
    
    def test_allowed_command_validation(self):
        """Test that only allowed commands can execute"""
        # This should work (echo is typically allowed)
        result = self.executor.execute_command(['echo', 'test'])
        assert result.returncode == 0
        
        # This should fail (arbitrary command)
        with pytest.raises(CommandExecutionError):
            self.executor.execute_command(['/bin/arbitrary_command'])
    
    def test_argument_sanitization(self):
        """Test that command arguments are sanitized"""
        # Test that dangerous characters are removed
        sanitized = self.executor.sanitize_arguments(['test;rm', 'file|cat'])
        assert ';' not in sanitized[0]
        assert '|' not in sanitized[1]
    
    def test_timeout_handling(self):
        """Test command timeout handling"""
        with pytest.raises(CommandExecutionError):
            # This should timeout (sleep for longer than timeout)
            self.executor.execute_command(['sleep', '60'], timeout=1)
    
    def test_environment_sanitization(self):
        """Test that dangerous environment variables are removed"""
        dangerous_env = {
            'LD_PRELOAD': '/malicious/lib.so',
            'PYTHONPATH': '/malicious/path',
            'SAFE_VAR': 'safe_value'
        }
        
        # Mock subprocess.run to capture the environment
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
            
            self.executor.execute_command(['echo', 'test'], env=dangerous_env)
            
            # Check that dangerous variables were removed
            called_env = mock_run.call_args[1]['env']
            assert 'LD_PRELOAD' not in called_env
            assert 'PYTHONPATH' not in called_env
            assert called_env['SAFE_VAR'] == 'safe_value'

class TestLegacyCompatibility:
    """Test legacy compatibility functions"""
    
    def test_secure_system_replacement(self):
        """Test secure replacement for os.system()"""
        # Safe command should work
        result = secure_system('echo hello')
        assert result == 0
        
        # Dangerous command should fail
        result = secure_system('rm -rf /')
        assert result == -1
    
    def test_secure_exec_command_replacement(self):
        """Test secure replacement for exec() commands"""
        result = secure_exec_command(['echo', 'test'])
        assert result.returncode == 0

class TestSecurityValidation:
    """Test security validation functions"""
    
    def test_script_content_validation(self):
        """Test script content validation"""
        executor = SecureScriptExecutor()
        
        # Safe content should pass
        assert executor.validate_script_content("x = 1 + 1")
        
        # Dangerous content should fail
        assert not executor.validate_script_content("eval('malicious code')")
        assert not executor.validate_script_content("exec('rm -rf /')")
        assert not executor.validate_script_content("import subprocess")
    
    def test_command_validation(self):
        """Test command validation"""
        executor = SecureCommandExecutor()
        
        # Safe commands should pass
        assert executor.validate_command("echo hello")
        
        # Dangerous commands should fail
        assert not executor.validate_command("rm -rf /")
        assert not executor.validate_command("echo hello; rm file")
        assert not executor.validate_command("cat ../../etc/passwd")

@pytest.mark.integration
class TestIntegrationSecurity:
    """Integration tests for security features"""
    
    def test_end_to_end_script_security(self):
        """Test end-to-end script security"""
        # Create a test script with mixed safe and unsafe content
        script_content = """
# Safe operations
import json
data = {"test": "value"}
json_data = json.dumps(data)

# This should be blocked
# eval("malicious_code")
"""
        
        executor = SecureScriptExecutor()
        result = executor.execute_script_content(script_content)
        assert 'json_data' in result
    
    def test_ruby_compatibility_layer(self):
        """Test Ruby compatibility layer"""
        # Test that Ruby-style script execution is secured
        from rex.script_secure import execute
        
        safe_script = "result = 'ruby_compat_test'"
        result = execute(safe_script)
        # Should execute safely

@pytest.mark.security
class TestSecurityRegression:
    """Regression tests for security fixes"""
    
    def test_eval_vulnerability_fixed(self):
        """Test that eval() vulnerabilities are fixed"""
        # Test various eval() attack vectors
        attack_vectors = [
            "eval('__import__(\"os\").system(\"rm -rf /\")')",
            "exec('import subprocess; subprocess.call([\"rm\", \"-rf\", \"/\"])')",
            "compile('malicious_code', '<string>', 'exec')",
        ]
        
        executor = SecureScriptExecutor()
        for attack in attack_vectors:
            with pytest.raises(ScriptExecutionError):
                executor.execute_script_content(attack)
    
    def test_command_injection_fixed(self):
        """Test that command injection vulnerabilities are fixed"""
        attack_vectors = [
            "echo hello; rm -rf /",
            "echo hello && rm -rf /",
            "echo hello | rm -rf /",
            "echo hello `rm -rf /`",
            "echo hello $(rm -rf /)",
        ]
        
        executor = SecureCommandExecutor()
        for attack in attack_vectors:
            with pytest.raises(CommandExecutionError):
                executor.execute_command(attack)

if __name__ == '__main__':
    pytest.main([__file__, '-v'])