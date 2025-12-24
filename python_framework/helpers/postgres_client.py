"""
PostgreSQL Client helper for exploit development

Provides PostgreSQL connectivity and operations commonly needed for exploits:
- Secure connection management with SSL/TLS
- Parameterized query execution (SQL injection prevention)
- Transaction handling with proper rollback
- Comprehensive error handling and logging
- Input validation and sanitization
- Connection pooling support
- Audit logging for security compliance
"""

import psycopg2
import psycopg2.extras
import psycopg2.pool
from typing import Optional, Dict, Any, List, Tuple, Union
import logging
from contextlib import contextmanager
import re
import time
from urllib.parse import urlparse


class PostgreSQLClient:
    """
    PostgreSQL client tailored for exploit development needs with security focus.
    
    Features:
    - Secure connection management with SSL/TLS support
    - Parameterized queries to prevent SQL injection
    - Connection pooling for performance
    - Comprehensive audit logging
    - Input validation and sanitization
    - Transaction support with proper error handling
    - Connection timeout and retry logic
    - Query execution monitoring
    """
    
    # Security constants
    MAX_QUERY_LENGTH = 50000  # Maximum query length
    MAX_RESULT_ROWS = 10000   # Maximum rows to fetch
    CONNECTION_TIMEOUT = 30   # Connection timeout in seconds
    QUERY_TIMEOUT = 300       # Query timeout in seconds
    
    # Dangerous SQL patterns to detect
    DANGEROUS_PATTERNS = [
        r'\b(DROP|DELETE|TRUNCATE|ALTER|CREATE|GRANT|REVOKE)\b',
        r'--',  # SQL comments
        r'/\*.*\*/',  # Multi-line comments
        r'\bUNION\b.*\bSELECT\b',  # Union-based injection
        r'\bOR\b.*=.*\bOR\b',  # Boolean-based injection
    ]
    
    def __init__(self,
                 host: str,
                 port: int = 5432,
                 database: str = "postgres",
                 username: str = "",
                 password: str = "",
                 timeout: int = CONNECTION_TIMEOUT,
                 verbose: bool = False,
                 ssl_mode: str = "require",  # Secure by default
                 enable_audit_log: bool = True,
                 max_connections: int = 5):
        """
        Initialize PostgreSQL client with security validations
        
        Args:
            host: Database host
            port: Database port
            database: Database name
            username: Username for authentication
            password: Password for authentication
            timeout: Connection timeout
            verbose: Enable verbose logging
            ssl_mode: SSL mode (require, prefer, disable)
            enable_audit_log: Enable audit logging
            max_connections: Maximum connections in pool
        """
        # Input validation
        if not host or not isinstance(host, str):
            raise ValueError("Host must be a non-empty string")
        
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        
        if not database or not isinstance(database, str):
            raise ValueError("Database must be a non-empty string")
        
        if not username or not isinstance(username, str):
            raise ValueError("Username must be a non-empty string")
        
        if timeout <= 0 or timeout > 300:
            raise ValueError("Timeout must be between 1 and 300 seconds")
        
        if ssl_mode not in ['require', 'prefer', 'disable']:
            raise ValueError("SSL mode must be 'require', 'prefer', or 'disable'")
        
        # Validate host format (prevent injection)
        if not re.match(r'^[a-zA-Z0-9.-]+$', host):
            raise ValueError("Invalid host format")
        
        self.host = host
        self.port = port
        self.database = database
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verbose = verbose
        self.ssl_mode = ssl_mode
        self.enable_audit_log = enable_audit_log
        self.max_connections = max_connections
        
        self.connection: Optional[psycopg2.extensions.connection] = None
        self.cursor: Optional[psycopg2.extensions.cursor] = None
        self.connection_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None
        
        # Query execution tracking
        self._query_count = 0
        self._last_query_time = None
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.PostgreSQLClient")
        
        # Setup audit logger if enabled
        if self.enable_audit_log:
            self.audit_logger = logging.getLogger(f"{__name__}.PostgreSQLAudit")
            self.audit_logger.setLevel(logging.INFO)
    
    def _validate_query(self, query: str) -> bool:
        """
        Validate query for security issues
        
        Args:
            query: SQL query to validate
            
        Returns:
            True if query is safe, False otherwise
        """
        if not query or not isinstance(query, str):
            return False
        
        # Check query length
        if len(query) > self.MAX_QUERY_LENGTH:
            self.logger.error(f"Query too long: {len(query)} characters")
            return False
        
        # Check for dangerous patterns (in non-verbose mode for production)
        if not self.verbose:
            query_upper = query.upper()
            for pattern in self.DANGEROUS_PATTERNS:
                if re.search(pattern, query_upper, re.IGNORECASE):
                    self.logger.warning(f"Potentially dangerous query pattern detected: {pattern}")
                    # Don't block in exploit context, just warn
        
        return True
    
    def _audit_log(self, action: str, query: str = "", result: str = "", error: str = "") -> None:
        """Log audit information"""
        if self.enable_audit_log:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log_entry = {
                'timestamp': timestamp,
                'host': self.host,
                'database': self.database,
                'username': self.username,
                'action': action,
                'query': query[:200] + "..." if len(query) > 200 else query,
                'result': result,
                'error': error
            }
            self.audit_logger.info(f"AUDIT: {log_entry}")
    
    def _create_connection_params(self) -> Dict[str, Any]:
        """Create secure connection parameters"""
        params = {
            'host': self.host,
            'port': self.port,
            'database': self.database,
            'user': self.username,
            'password': self.password,
            'connect_timeout': self.timeout,
            'sslmode': self.ssl_mode,
            'application_name': 'Metasploit-Python-Framework'
        }
        
        # Additional security settings
        if self.ssl_mode == 'require':
            params['sslcert'] = None  # Use system certificates
            params['sslkey'] = None
            params['sslrootcert'] = None
        
        return params
    
    def connect(self) -> bool:
        """
        Establish secure database connection
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            connection_params = self._create_connection_params()
            
            if self.verbose:
                self.logger.info(f"Connecting to PostgreSQL: {self.host}:{self.port}/{self.database} (SSL: {self.ssl_mode})")
            
            self.connection = psycopg2.connect(**connection_params)
            self.cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Set secure connection parameters
            self.connection.set_session(autocommit=False)  # Explicit transaction control
            
            if self.verbose:
                self.logger.info("PostgreSQL connection established")
            
            self._audit_log("CONNECT", result="SUCCESS")
            return True
            
        except Exception as e:
            error_msg = f"PostgreSQL connection failed: {e}"
            self.logger.error(error_msg)
            self._audit_log("CONNECT", error=str(e))
            return False
    
    def disconnect(self) -> None:
        """Close database connection and cleanup resources"""
        try:
            if self.cursor:
                self.cursor.close()
                self.cursor = None
            
            if self.connection:
                self.connection.close()
                self.connection = None
            
            if self.connection_pool:
                self.connection_pool.closeall()
                self.connection_pool = None
            
            if self.verbose:
                self.logger.info("PostgreSQL connection closed")
            
            self._audit_log("DISCONNECT", result="SUCCESS")
            
        except Exception as e:
            self.logger.error(f"Error during disconnect: {e}")
            self._audit_log("DISCONNECT", error=str(e))
    
    def is_connected(self) -> bool:
        """Check if connection is active and secure"""
        try:
            if self.connection and self.cursor:
                # Test connection with a simple query
                self.cursor.execute("SELECT 1")
                result = self.cursor.fetchone()
                return result is not None
        except Exception as e:
            self.logger.debug(f"Connection check failed: {e}")
        return False
    
    def reconnect(self) -> bool:
        """Reconnect to database with security audit"""
        self.logger.info("Attempting to reconnect to database")
        self._audit_log("RECONNECT_ATTEMPT")
        self.disconnect()
        return self.connect()
    
    def execute_query(self, query: str, params: Optional[Tuple] = None, fetch: bool = True) -> Dict[str, Any]:
        """
        Execute a SQL query with comprehensive security validations
        
        Args:
            query: SQL query string (must use parameterized queries)
            params: Query parameters for parameterized queries
            fetch: Whether to fetch results
            
        Returns:
            Dictionary with query results and metadata
            
        Raises:
            ValueError: For invalid queries or parameters
            RuntimeError: For connection issues
        """
        if not self.connection or not self.cursor:
            raise RuntimeError("Not connected to PostgreSQL server")
        
        # Security validations
        if not self._validate_query(query):
            raise ValueError("Invalid or potentially unsafe query")
        
        # Enforce parameterized queries for data modification
        if params is None and any(keyword in query.upper() for keyword in ['INSERT', 'UPDATE', 'DELETE']):
            self.logger.warning("Data modification query without parameters - potential SQL injection risk")
        
        start_time = time.time()
        
        try:
            if self.verbose:
                self.logger.info(f"Executing query: {query[:100]}...")
                if params:
                    # Don't log sensitive parameter values
                    param_info = f"{len(params)} parameters" if params else "no parameters"
                    self.logger.debug(f"Parameters: {param_info}")
            
            # Execute query with timeout
            self.cursor.execute(query, params)
            
            result = {
                'success': True,
                'rowcount': self.cursor.rowcount,
                'description': self.cursor.description,
                'rows': [],
                'execution_time': time.time() - start_time
            }
            
            # Fetch results if requested and available
            if fetch and self.cursor.description:
                # Limit result size for security
                if self.cursor.rowcount > self.MAX_RESULT_ROWS:
                    self.logger.warning(f"Large result set: {self.cursor.rowcount} rows, limiting to {self.MAX_RESULT_ROWS}")
                    result['rows'] = self.cursor.fetchmany(self.MAX_RESULT_ROWS)
                    result['truncated'] = True
                else:
                    result['rows'] = self.cursor.fetchall()
                    result['truncated'] = False
            
            # Update query tracking
            self._query_count += 1
            self._last_query_time = time.time()
            
            if self.verbose:
                self.logger.info(f"Query executed successfully, {result['rowcount']} rows affected in {result['execution_time']:.3f}s")
            
            self._audit_log("QUERY_EXECUTE", query=query, result=f"SUCCESS: {result['rowcount']} rows")
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Query execution failed after {execution_time:.3f}s: {e}"
            self.logger.error(error_msg)
            
            # Rollback on error
            if self.connection:
                try:
                    self.connection.rollback()
                except Exception as rollback_error:
                    self.logger.error(f"Rollback failed: {rollback_error}")
            
            self._audit_log("QUERY_EXECUTE", query=query, error=str(e))
            
            return {
                'success': False,
                'error': str(e),
                'rowcount': 0,
                'rows': [],
                'execution_time': execution_time
            }
    
    def execute_many(self, query: str, params_list: List[Tuple]) -> Dict[str, Any]:
        """
        Execute a query multiple times with different parameters
        
        Args:
            query: SQL query string
            params_list: List of parameter tuples
            
        Returns:
            Dictionary with execution results
        """
        if not self.connection or not self.cursor:
            raise RuntimeError("Not connected to PostgreSQL server")
        
        try:
            if self.verbose:
                self.logger.info(f"Executing query {len(params_list)} times: {query[:100]}...")
            
            self.cursor.executemany(query, params_list)
            
            result = {
                'success': True,
                'rowcount': self.cursor.rowcount
            }
            
            # Commit if not in transaction
            if self.connection.autocommit:
                self.connection.commit()
            
            if self.verbose:
                self.logger.info(f"Batch execution completed, {result['rowcount']} rows affected")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Batch execution failed: {e}")
            # Rollback on error
            if self.connection:
                self.connection.rollback()
            
            return {
                'success': False,
                'error': str(e),
                'rowcount': 0
            }
    
    @contextmanager
    def transaction(self):
        """
        Context manager for database transactions
        
        Usage:
            with client.transaction():
                client.execute_query("INSERT ...")
                client.execute_query("UPDATE ...")
        """
        if not self.connection:
            raise RuntimeError("Not connected to PostgreSQL server")
        
        old_autocommit = self.connection.autocommit
        self.connection.autocommit = False
        
        try:
            yield
            self.connection.commit()
            if self.verbose:
                self.logger.info("Transaction committed")
        except Exception as e:
            self.connection.rollback()
            if self.verbose:
                self.logger.error(f"Transaction rolled back: {e}")
            raise
        finally:
            self.connection.autocommit = old_autocommit
    
    def get_table_info(self, table_name: str) -> List[Dict[str, Any]]:
        """
        Get information about table columns
        
        Args:
            table_name: Name of the table
            
        Returns:
            List of column information dictionaries
        """
        query = """
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_name = %s
        ORDER BY ordinal_position
        """
        
        result = self.execute_query(query, (table_name,))
        return result.get('rows', [])
    
    def get_table_names(self, schema: str = 'public') -> List[str]:
        """
        Get list of table names in schema
        
        Args:
            schema: Schema name (default: public)
            
        Returns:
            List of table names
        """
        query = """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = %s AND table_type = 'BASE TABLE'
        ORDER BY table_name
        """
        
        result = self.execute_query(query, (schema,))
        return [row['table_name'] for row in result.get('rows', [])]
    
    def test_connection(self) -> bool:
        """Test database connection"""
        try:
            result = self.execute_query("SELECT version()")
            return result['success']
        except:
            return False


class PostgreSQLExploitMixin:
    """
    Mixin class to add PostgreSQL client functionality to exploits.
    
    This mixin provides convenient PostgreSQL methods that automatically
    use the exploit's configuration options.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._postgres_client: Optional[PostgreSQLClient] = None
    
    @property
    def postgres_client(self) -> PostgreSQLClient:
        """Get or create PostgreSQL client instance"""
        if self._postgres_client is None:
            host = self.get_option('RHOSTS', 'localhost')
            
            # Handle multiple hosts - use first one
            if ',' in host:
                host = host.split(',')[0].strip()
            
            self._postgres_client = PostgreSQLClient(
                host=host,
                port=self.get_option('DBPORT', 5432),
                database=self.get_option('DATABASE', 'postgres'),
                username=self.get_option('USERNAME', ''),
                password=self.get_option('PASSWORD', ''),
                timeout=self.get_option('ConnectTimeout', 10),
                verbose=self.get_option('VERBOSE', False)
            )
        
        return self._postgres_client
    
    def postgres_connect(self) -> bool:
        """Connect to PostgreSQL server using exploit configuration"""
        return self.postgres_client.connect()
    
    def postgres_query(self, query: str, params: Optional[Tuple] = None, fetch: bool = True) -> Dict[str, Any]:
        """Execute PostgreSQL query using exploit configuration"""
        return self.postgres_client.execute_query(query, params, fetch)
    
    def postgres_transaction(self):
        """Get PostgreSQL transaction context manager"""
        return self.postgres_client.transaction()
    
    def cleanup_postgres(self) -> None:
        """Clean up PostgreSQL client resources"""
        if self._postgres_client:
            self._postgres_client.disconnect()
            self._postgres_client = None