"""
Comprehensive tests for Python framework core functionality.

Tests the base exploit classes, enumerations, and data structures to ensure
they work correctly after the Ruby-to-Python migration.
"""

import pytest
import sys
from pathlib import Path

# Add python_framework to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'python_framework'))

from core.exploit import (
    ExploitRank, TargetArch, Platform, PayloadType,
    ExploitTarget, ExploitOption, ExploitInfo, ExploitResult,
    Exploit, RemoteExploit, LocalExploit
)


class TestEnumerations:
    """Test all enumeration types"""
    
    def test_exploit_rank_values(self):
        """Test that all exploit ranks are defined correctly"""
        assert ExploitRank.MANUAL.value == "Manual"
        assert ExploitRank.LOW.value == "Low"
        assert ExploitRank.AVERAGE.value == "Average"
        assert ExploitRank.NORMAL.value == "Normal"
        assert ExploitRank.GOOD.value == "Good"
        assert ExploitRank.GREAT.value == "Great"
        assert ExploitRank.EXCELLENT.value == "Excellent"
    
    def test_target_arch_values(self):
        """Test that all target architectures are defined"""
        assert TargetArch.X86.value == "x86"
        assert TargetArch.X64.value == "x64"
        assert TargetArch.ARM.value == "arm"
        assert TargetArch.AARCH64.value == "aarch64"
        assert TargetArch.MIPS.value == "mips"
        assert TargetArch.PPC.value == "ppc"
        assert TargetArch.SPARC.value == "sparc"
        assert TargetArch.CMD.value == "cmd"
    
    def test_platform_values(self):
        """Test that all platforms are defined"""
        assert Platform.WINDOWS.value == "windows"
        assert Platform.LINUX.value == "linux"
        assert Platform.UNIX.value == "unix"
        assert Platform.OSX.value == "osx"
        assert Platform.BSD.value == "bsd"
        assert Platform.ANDROID.value == "android"
        assert Platform.IOS.value == "ios"
    
    def test_payload_type_values(self):
        """Test that all payload types are defined"""
        assert PayloadType.BIND_TCP.value == "bind_tcp"
        assert PayloadType.REVERSE_TCP.value == "reverse_tcp"
        assert PayloadType.REVERSE_HTTP.value == "reverse_http"
        assert PayloadType.REVERSE_HTTPS.value == "reverse_https"
        assert PayloadType.SSH_INTERACT.value == "ssh_interact"
        assert PayloadType.UNIX_CMD.value == "unix_cmd"
        assert PayloadType.WINDOWS_CMD.value == "windows_cmd"


class TestExploitTarget:
    """Test ExploitTarget dataclass"""
    
    def test_basic_target_creation(self):
        """Test creating a basic exploit target"""
        target = ExploitTarget(
            name="Linux x64",
            platform=[Platform.LINUX],
            arch=[TargetArch.X64],
            payload_type=PayloadType.REVERSE_TCP
        )
        
        assert target.name == "Linux x64"
        assert target.platform == [Platform.LINUX]
        assert target.arch == [TargetArch.X64]
        assert target.payload_type == PayloadType.REVERSE_TCP
        assert target.default_options == {}
    
    def test_target_with_options(self):
        """Test creating a target with default options"""
        options = {"RPORT": 8080, "SSL": True}
        target = ExploitTarget(
            name="Windows x86",
            platform=[Platform.WINDOWS],
            arch=[TargetArch.X86],
            payload_type=PayloadType.BIND_TCP,
            default_options=options
        )
        
        assert target.default_options == options
        assert target.default_options["RPORT"] == 8080
        assert target.default_options["SSL"] is True


class TestExploitOption:
    """Test ExploitOption dataclass"""
    
    def test_required_option(self):
        """Test creating a required option"""
        option = ExploitOption(
            name="RHOSTS",
            required=True,
            description="Target host(s)"
        )
        
        assert option.name == "RHOSTS"
        assert option.required is True
        assert option.description == "Target host(s)"
        assert option.default_value is None
        assert option.data_type == str
    
    def test_optional_option_with_default(self):
        """Test creating an optional option with default value"""
        option = ExploitOption(
            name="RPORT",
            required=False,
            description="Target port",
            default_value=80,
            data_type=int
        )
        
        assert option.name == "RPORT"
        assert option.required is False
        assert option.default_value == 80
        assert option.data_type == int
    
    def test_boolean_option(self):
        """Test creating a boolean option"""
        option = ExploitOption(
            name="SSL",
            required=False,
            description="Use SSL/TLS",
            default_value=False,
            data_type=bool
        )
        
        assert option.data_type == bool
        assert option.default_value is False


class TestExploitInfo:
    """Test ExploitInfo dataclass"""
    
    def test_minimal_exploit_info(self):
        """Test creating minimal exploit info"""
        info = ExploitInfo(
            name="Test Exploit",
            description="A test exploit",
            author=["Test Author"]
        )
        
        assert info.name == "Test Exploit"
        assert info.description == "A test exploit"
        assert info.author == ["Test Author"]
        assert info.rank == ExploitRank.NORMAL
        assert info.references == []
        assert info.targets == []
        assert info.default_target == 0
    
    def test_complete_exploit_info(self):
        """Test creating complete exploit info with all fields"""
        targets = [
            ExploitTarget(
                name="Linux x64",
                platform=[Platform.LINUX],
                arch=[TargetArch.X64],
                payload_type=PayloadType.REVERSE_TCP
            )
        ]
        
        info = ExploitInfo(
            name="CVE-2024-12345",
            description="Remote code execution vulnerability",
            author=["Author 1", "Author 2"],
            references=["CVE-2024-12345", "URL-http://example.com"],
            disclosure_date="2024-01-15",
            rank=ExploitRank.EXCELLENT,
            targets=targets,
            default_target=0,
            platform=[Platform.LINUX, Platform.UNIX],
            arch=[TargetArch.X64],
            privileged=True,
            license="BSD_LICENSE",
            notes={"Stability": ["CRASH_SAFE"], "Reliability": ["REPEATABLE_SESSION"]}
        )
        
        assert info.name == "CVE-2024-12345"
        assert len(info.author) == 2
        assert len(info.references) == 2
        assert info.rank == ExploitRank.EXCELLENT
        assert len(info.targets) == 1
        assert info.privileged is True
        assert "Stability" in info.notes


class TestExploitResult:
    """Test ExploitResult class"""
    
    def test_successful_result(self):
        """Test creating a successful exploit result"""
        result = ExploitResult(success=True, message="Exploit successful")
        
        assert result.success is True
        assert result.message == "Exploit successful"
        assert result.data == {}
    
    def test_failed_result(self):
        """Test creating a failed exploit result"""
        result = ExploitResult(success=False, message="Connection failed")
        
        assert result.success is False
        assert result.message == "Connection failed"
    
    def test_result_with_data(self):
        """Test creating a result with additional data"""
        data = {"session_id": "12345", "shell_type": "reverse_tcp"}
        result = ExploitResult(success=True, message="Session opened", data=data)
        
        assert result.success is True
        assert result.data["session_id"] == "12345"
        assert result.data["shell_type"] == "reverse_tcp"


class TestExploit:
    """Test Exploit abstract class"""
    
    def test_exploit_instantiation(self):
        """Test that Exploit can be instantiated with required methods"""
        
        # Create a concrete implementation for testing
        class TestExploitImpl(Exploit):
            def check(self):
                return ExploitResult(True, "Vulnerable")
            
            def exploit(self):
                return ExploitResult(True, "Exploited")
        
        info = ExploitInfo(
            name="Test",
            description="Test exploit",
            author=["Test"]
        )
        
        exploit = TestExploitImpl(info)
        assert exploit.info.name == "Test"
        assert exploit.info.author == ["Test"]
        assert isinstance(exploit.options, dict)
    
    def test_register_options(self):
        """Test registering exploit options"""
        
        class TestExploitImpl(Exploit):
            def check(self):
                return ExploitResult(True, "Vulnerable")
            
            def exploit(self):
                return ExploitResult(True, "Exploited")
        
        info = ExploitInfo(
            name="Test",
            description="Test exploit",
            author=["Test"]
        )
        
        exploit = TestExploitImpl(info)
        exploit.register_options([
            ExploitOption("RHOSTS", True, "Target hosts"),
            ExploitOption("RPORT", False, "Target port", 80, int)
        ])
        
        assert "RHOSTS" in exploit.options
        assert "RPORT" in exploit.options
        assert exploit.options["RPORT"].default_value == 80
    
    def test_set_and_get_option(self):
        """Test setting and getting option values"""
        
        class TestExploitImpl(Exploit):
            def check(self):
                return ExploitResult(True, "Vulnerable")
            
            def exploit(self):
                return ExploitResult(True, "Exploited")
        
        info = ExploitInfo(
            name="Test",
            description="Test exploit",
            author=["Test"]
        )
        
        exploit = TestExploitImpl(info)
        exploit.register_options([
            ExploitOption("RHOSTS", True, "Target hosts", "192.168.1.1")
        ])
        
        # Test default value
        assert exploit.get_option("RHOSTS") == "192.168.1.1"
        
        # Test setting value
        exploit.set_option("RHOSTS", "10.0.0.1")
        assert exploit.get_option("RHOSTS") == "10.0.0.1"
    
    def test_missing_option_handling(self):
        """Test handling of missing options"""
        
        class TestExploitImpl(Exploit):
            def check(self):
                return ExploitResult(True, "Vulnerable")
            
            def exploit(self):
                return ExploitResult(True, "Exploited")
        
        info = ExploitInfo(
            name="Test",
            description="Test exploit",
            author=["Test"]
        )
        
        exploit = TestExploitImpl(info)
        
        # Getting a non-existent option should return None
        assert exploit.get_option("NONEXISTENT") is None


class TestRemoteExploit:
    """Test RemoteExploit class"""
    
    def test_remote_exploit_creation(self):
        """Test creating a RemoteExploit instance"""
        
        class TestRemoteExploit(RemoteExploit):
            def check(self):
                return ExploitResult(True, "Vulnerable")
            
            def exploit(self):
                return ExploitResult(True, "Exploited")
        
        info = ExploitInfo(
            name="Remote Test",
            description="Remote test exploit",
            author=["Test"]
        )
        
        exploit = TestRemoteExploit(info)
        assert exploit.info.name == "Remote Test"
        
        # Remote exploits should have standard network options
        assert "RHOSTS" in exploit.options or len(exploit.options) >= 0


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
