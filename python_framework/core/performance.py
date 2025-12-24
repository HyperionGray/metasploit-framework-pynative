"""
Performance optimization module for Metasploit Framework

This module provides performance enhancements including:
- Connection pooling for database and network operations
- Caching mechanisms for expensive operations
- Memory management optimizations
- Asynchronous operation support
- Performance monitoring and metrics
"""

import asyncio
import threading
import time
import weakref
from typing import Dict, Any, Optional, Callable, List, Tuple
from functools import wraps, lru_cache
from collections import defaultdict
import logging
import psutil
import gc


class ConnectionPool:
    """Generic connection pool for managing reusable connections"""
    
    def __init__(self, 
                 connection_factory: Callable,
                 max_connections: int = 10,
                 max_idle_time: int = 300,
                 health_check_interval: int = 60):
        self.connection_factory = connection_factory
        self.max_connections = max_connections
        self.max_idle_time = max_idle_time
        self.health_check_interval = health_check_interval
        
        self._pool = []
        self._in_use = set()
        self._lock = threading.RLock()
        self._last_health_check = time.time()
        
        self.logger = logging.getLogger(f"{__name__}.ConnectionPool")
    
    def get_connection(self):
        """Get a connection from the pool"""
        with self._lock:
            # Perform health check if needed
            if time.time() - self._last_health_check > self.health_check_interval:
                self._health_check()
            
            # Try to get an existing connection
            if self._pool:
                conn = self._pool.pop()
                self._in_use.add(conn)
                return conn
            
            # Create new connection if under limit
            if len(self._in_use) < self.max_connections:
                conn = self.connection_factory()
                self._in_use.add(conn)
                return conn
            
            # Pool is full, wait or raise exception
            raise RuntimeError("Connection pool exhausted")
    
    def return_connection(self, connection):
        """Return a connection to the pool"""
        with self._lock:
            if connection in self._in_use:
                self._in_use.remove(connection)
                connection.last_used = time.time()
                self._pool.append(connection)
    
    def _health_check(self):
        """Remove stale connections from pool"""
        current_time = time.time()
        self._pool = [
            conn for conn in self._pool
            if current_time - getattr(conn, 'last_used', current_time) < self.max_idle_time
        ]
        self._last_health_check = current_time


class PerformanceCache:
    """High-performance caching system with TTL and size limits"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache = {}
        self._access_times = {}
        self._lock = threading.RLock()
        
        self.logger = logging.getLogger(f"{__name__}.PerformanceCache")
    
    def get(self, key: str, default=None):
        """Get value from cache"""
        with self._lock:
            if key not in self._cache:
                return default
            
            value, expiry = self._cache[key]
            if time.time() > expiry:
                del self._cache[key]
                del self._access_times[key]
                return default
            
            self._access_times[key] = time.time()
            return value
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache"""
        with self._lock:
            if len(self._cache) >= self.max_size:
                self._evict_lru()
            
            ttl = ttl or self.default_ttl
            expiry = time.time() + ttl
            self._cache[key] = (value, expiry)
            self._access_times[key] = time.time()
    
    def _evict_lru(self):
        """Evict least recently used item"""
        if not self._access_times:
            return
        
        lru_key = min(self._access_times.keys(), key=lambda k: self._access_times[k])
        del self._cache[lru_key]
        del self._access_times[lru_key]
    
    def clear(self):
        """Clear all cached items"""
        with self._lock:
            self._cache.clear()
            self._access_times.clear()


def performance_monitor(func):
    """Decorator to monitor function performance"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss
        
        try:
            result = func(*args, **kwargs)
            success = True
            error = None
        except Exception as e:
            result = None
            success = False
            error = str(e)
            raise
        finally:
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss
            
            # Log performance metrics
            logger = logging.getLogger(f"{__name__}.performance")
            logger.info(f"Function {func.__name__}: "
                       f"time={end_time - start_time:.3f}s, "
                       f"memory_delta={end_memory - start_memory} bytes, "
                       f"success={success}")
        
        return result
    return wrapper


class MemoryManager:
    """Memory management utilities for performance optimization"""
    
    @staticmethod
    def force_gc():
        """Force garbage collection"""
        collected = gc.collect()
        logging.getLogger(__name__).debug(f"Garbage collection freed {collected} objects")
        return collected
    
    @staticmethod
    def get_memory_usage():
        """Get current memory usage"""
        process = psutil.Process()
        memory_info = process.memory_info()
        return {
            'rss': memory_info.rss,
            'vms': memory_info.vms,
            'percent': process.memory_percent()
        }
    
    @staticmethod
    def memory_limit_check(max_memory_mb: int = 1000):
        """Check if memory usage exceeds limit"""
        memory_usage = MemoryManager.get_memory_usage()
        memory_mb = memory_usage['rss'] / (1024 * 1024)
        
        if memory_mb > max_memory_mb:
            logging.getLogger(__name__).warning(
                f"Memory usage ({memory_mb:.1f}MB) exceeds limit ({max_memory_mb}MB)"
            )
            return False
        return True


class AsyncOperationManager:
    """Manager for asynchronous operations"""
    
    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.logger = logging.getLogger(f"{__name__}.AsyncOperationManager")
    
    async def execute_async(self, coro):
        """Execute coroutine with concurrency control"""
        async with self.semaphore:
            return await coro
    
    async def batch_execute(self, coroutines: List):
        """Execute multiple coroutines concurrently"""
        tasks = [self.execute_async(coro) for coro in coroutines]
        return await asyncio.gather(*tasks, return_exceptions=True)


class PerformanceMetrics:
    """Performance metrics collection and reporting"""
    
    def __init__(self):
        self.metrics = defaultdict(list)
        self._lock = threading.Lock()
        self.logger = logging.getLogger(f"{__name__}.PerformanceMetrics")
    
    def record_metric(self, name: str, value: float, tags: Dict[str, str] = None):
        """Record a performance metric"""
        with self._lock:
            metric_data = {
                'timestamp': time.time(),
                'value': value,
                'tags': tags or {}
            }
            self.metrics[name].append(metric_data)
    
    def get_metrics_summary(self, name: str, window_seconds: int = 300) -> Dict[str, float]:
        """Get summary statistics for a metric"""
        with self._lock:
            cutoff_time = time.time() - window_seconds
            recent_values = [
                m['value'] for m in self.metrics[name]
                if m['timestamp'] > cutoff_time
            ]
            
            if not recent_values:
                return {}
            
            return {
                'count': len(recent_values),
                'min': min(recent_values),
                'max': max(recent_values),
                'avg': sum(recent_values) / len(recent_values),
                'total': sum(recent_values)
            }
    
    def cleanup_old_metrics(self, max_age_seconds: int = 3600):
        """Remove old metrics to prevent memory growth"""
        with self._lock:
            cutoff_time = time.time() - max_age_seconds
            for name in self.metrics:
                self.metrics[name] = [
                    m for m in self.metrics[name]
                    if m['timestamp'] > cutoff_time
                ]


# Global instances
_performance_cache = PerformanceCache()
_performance_metrics = PerformanceMetrics()


def cached(ttl: int = 300, key_func: Optional[Callable] = None):
    """Decorator for caching function results"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
            
            # Try to get from cache
            result = _performance_cache.get(cache_key)
            if result is not None:
                _performance_metrics.record_metric('cache_hit', 1, {'function': func.__name__})
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            _performance_cache.set(cache_key, result, ttl)
            _performance_metrics.record_metric('cache_miss', 1, {'function': func.__name__})
            
            return result
        return wrapper
    return decorator


def batch_operation(batch_size: int = 100):
    """Decorator for batching operations"""
    def decorator(func):
        @wraps(func)
        def wrapper(items, *args, **kwargs):
            results = []
            for i in range(0, len(items), batch_size):
                batch = items[i:i + batch_size]
                batch_result = func(batch, *args, **kwargs)
                results.extend(batch_result if isinstance(batch_result, list) else [batch_result])
            return results
        return wrapper
    return decorator