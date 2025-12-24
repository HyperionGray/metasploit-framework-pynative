"""
Comprehensive integration tests for the Metasploit Framework

This test suite provides comprehensive coverage for:
- Framework component integration
- End-to-end exploit workflows
- Performance benchmarking
- Security validation
- Error handling and recovery
"""

import unittest
import tempfile
import os
import sys
import time
import threading
from unittest.mock import Mock, patch, MagicMock
import logging

# Add framework paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python_framework'))

from core.exploit import Exploit, ExploitInfo, ExploitTarget, ExploitOption, RemoteExploit
from core.performance import PerformanceCache, ConnectionPool, MemoryManager
from core.architecture import ComponentFactory, EventPublisher, DIContainer
from helpers.http_client import HttpClient
from helpers.postgres_client import PostgreSQLClient
from helpers.ssh_client import SSHClient


class TestFrameworkIntegration(unittest.TestCase):
    """Integration tests for framework components"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.logger = logging.getLogger(__name__)
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_exploit_workflow_integration(self):
        """Test complete exploit workflow"""
        # Create a test exploit
        class TestExploit(RemoteExploit):
            def __init__(self):
                info = ExploitInfo(
                    name="Test Exploit",
                    description="Test exploit for integration testing",
                    author=["Test Author"]
                )
                super().__init__(info)
            
            def check(self):
                from core.exploit import ExploitResult
                return ExploitResult(True, "Target appears vulnerable")
            
            def exploit(self):
                from core.exploit import ExploitResult
                return ExploitResult(True, "Exploit successful")
        
        # Test exploit execution
        exploit = TestExploit()
        exploit.set_option("RHOSTS", "127.0.0.1")
        exploit.set_option("RPORT", 80)
        
        result = exploit.run()
        self.assertTrue(result.success)
    
    def test_component_factory_integration(self):
        """Test component factory with real components"""
        # Register components
        ComponentFactory.register("http_client", HttpClient)
        ComponentFactory.register("postgres_client", PostgreSQLClient)
        ComponentFactory.register("ssh_client", SSHClient)
        
        # Test component creation
        http_client = ComponentFactory.create("http_client", base_url="https://example.com")
        self.assertIsInstance(http_client, HttpClient)
        
        # Test with parameters
        pg_client = ComponentFactory.create(
            "postgres_client",
            host="localhost",
            username="test",
            password="test"
        )
        self.assertIsInstance(pg_client, PostgreSQLClient)
    
    def test_performance_cache_integration(self):
        """Test performance cache with real operations"""
        cache = PerformanceCache(max_size=100, default_ttl=1)
        
        # Test caching expensive operations
        def expensive_operation(x):
            time.sleep(0.1)  # Simulate expensive operation
            return x * 2
        
        # First call should be slow
        start_time = time.time()
        result1 = expensive_operation(5)
        cache.set("test_op_5", result1)
        first_call_time = time.time() - start_time
        
        # Second call should be fast (from cache)
        start_time = time.time()
        result2 = cache.get("test_op_5")
        second_call_time = time.time() - start_time
        
        self.assertEqual(result1, result2)
        self.assertLess(second_call_time, first_call_time)
    
    def test_event_system_integration(self):
        """Test event system with multiple components"""
        publisher = EventPublisher()
        events_received = []
        
        class TestObserver:
            def handle_event(self, event):
                events_received.append(event)
        
        observer = TestObserver()
        publisher.subscribe("test_event", observer)
        
        # Publish events
        from core.architecture import Event
        event1 = Event("test_event", {"data": "test1"})
        event2 = Event("test_event", {"data": "test2"})
        
        publisher.publish(event1)
        publisher.publish(event2)
        
        self.assertEqual(len(events_received), 2)
        self.assertEqual(events_received[0].data["data"], "test1")
        self.assertEqual(events_received[1].data["data"], "test2")
    
    def test_dependency_injection_integration(self):
        """Test dependency injection with real services"""
        container = DIContainer()
        
        # Register services
        container.register_factory("logger", lambda: logging.getLogger("test"))
        container.register_singleton("config", lambda: {"debug": True})
        
        # Test resolution
        logger = container.resolve("logger")
        config1 = container.resolve("config")
        config2 = container.resolve("config")
        
        self.assertIsInstance(logger, logging.Logger)
        self.assertIs(config1, config2)  # Should be same instance (singleton)
    
    def test_memory_management_integration(self):
        """Test memory management during operations"""
        initial_memory = MemoryManager.get_memory_usage()
        
        # Create many objects to increase memory usage
        large_objects = []
        for i in range(1000):
            large_objects.append([0] * 1000)
        
        peak_memory = MemoryManager.get_memory_usage()
        
        # Clear objects and force garbage collection
        large_objects.clear()
        collected = MemoryManager.force_gc()
        
        final_memory = MemoryManager.get_memory_usage()
        
        # Memory should have increased then decreased
        self.assertGreater(peak_memory['rss'], initial_memory['rss'])
        self.assertGreater(collected, 0)
    
    def test_concurrent_operations(self):
        """Test framework under concurrent load"""
        results = []
        errors = []
        
        def worker_function(worker_id):
            try:
                # Simulate concurrent exploit operations
                cache = PerformanceCache()
                
                for i in range(10):
                    key = f"worker_{worker_id}_item_{i}"
                    value = f"data_{worker_id}_{i}"
                    cache.set(key, value)
                    
                    retrieved = cache.get(key)
                    if retrieved != value:
                        errors.append(f"Cache mismatch in worker {worker_id}")
                
                results.append(f"Worker {worker_id} completed")
                
            except Exception as e:
                errors.append(f"Worker {worker_id} error: {e}")
        
        # Start multiple worker threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker_function, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=10)
        
        # Verify results
        self.assertEqual(len(results), 5)
        self.assertEqual(len(errors), 0)
    
    @patch('requests.Session.request')
    def test_http_client_integration(self, mock_request):
        """Test HTTP client integration with security features"""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.text = '{"status": "success"}'
        mock_request.return_value = mock_response
        
        # Test secure HTTP client
        client = HttpClient(
            base_url="https://api.example.com",
            verify_ssl=True,
            enable_rate_limiting=True
        )
        
        # Test request with security validations
        response = client.get("/test", headers={"X-Test": "value"})
        
        self.assertEqual(response.status_code, 200)
        mock_request.assert_called_once()
        
        # Verify security headers were applied
        call_args = mock_request.call_args
        headers = call_args[1]['headers']
        self.assertIn('Cache-Control', headers)
    
    def test_error_handling_integration(self):
        """Test error handling across components"""
        # Test HTTP client error handling
        client = HttpClient()
        
        with self.assertRaises(ValueError):
            client.request("INVALID_METHOD", "/test")
        
        # Test PostgreSQL client error handling
        with self.assertRaises(ValueError):
            PostgreSQLClient(host="", username="test")
        
        # Test SSH client error handling
        with self.assertRaises(ValueError):
            SSHClient(hostname="", username="test")
    
    def test_configuration_integration(self):
        """Test configuration management across components"""
        from core.architecture import ConfigurableComponent
        
        # Create configurable component
        component = ConfigurableComponent("test_component")
        
        # Register validator
        component.register_validator("port", lambda x: isinstance(x, int) and 1 <= x <= 65535)
        
        # Test valid configuration
        component.set_option("port", 8080)
        self.assertEqual(component.get_option("port"), 8080)
        
        # Test invalid configuration
        with self.assertRaises(ValueError):
            component.set_option("port", 70000)  # Invalid port
    
    def test_logging_integration(self):
        """Test logging integration across components"""
        # Configure test logger
        logger = logging.getLogger("test_integration")
        handler = logging.StreamHandler()
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        
        # Test component logging
        from core.architecture import BaseComponent
        component = BaseComponent("test_component", logger)
        
        # Test initialization logging
        self.assertTrue(component.initialize())
        self.assertTrue(component.is_initialized())
        
        # Test cleanup logging
        component.cleanup()
        self.assertFalse(component.is_initialized())


class TestPerformanceBenchmarks(unittest.TestCase):
    """Performance benchmark tests"""
    
    def test_cache_performance(self):
        """Benchmark cache performance"""
        cache = PerformanceCache(max_size=1000)
        
        # Benchmark cache operations
        start_time = time.time()
        
        for i in range(1000):
            cache.set(f"key_{i}", f"value_{i}")
        
        set_time = time.time() - start_time
        
        start_time = time.time()
        
        for i in range(1000):
            cache.get(f"key_{i}")
        
        get_time = time.time() - start_time
        
        # Performance assertions
        self.assertLess(set_time, 1.0)  # Should complete in under 1 second
        self.assertLess(get_time, 0.5)  # Gets should be faster than sets
    
    def test_memory_efficiency(self):
        """Test memory efficiency of components"""
        initial_memory = MemoryManager.get_memory_usage()
        
        # Create multiple components
        components = []
        for i in range(100):
            client = HttpClient(base_url=f"https://example{i}.com")
            components.append(client)
        
        peak_memory = MemoryManager.get_memory_usage()
        
        # Clear components
        components.clear()
        MemoryManager.force_gc()
        
        final_memory = MemoryManager.get_memory_usage()
        
        # Memory should not grow excessively
        memory_growth = peak_memory['rss'] - initial_memory['rss']
        memory_recovered = peak_memory['rss'] - final_memory['rss']
        
        # Should recover at least 50% of allocated memory
        self.assertGreater(memory_recovered, memory_growth * 0.5)


if __name__ == '__main__':
    # Configure logging for tests
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run tests with detailed output
    unittest.main(verbosity=2)