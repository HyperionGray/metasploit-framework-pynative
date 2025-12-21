"""
PostgreSQL Client helper for exploit development

Provides PostgreSQL connectivity and operations commonly needed for exploits:
- Connection management
- Query execution
- Transaction handling
- Error handling
- Result processing
"""

import psycopg2
import psycopg2.extras
from typing import Optional, Dict, Any, List, Tuple, Union
import logging
from contextlib import contextmanager


class PostgreSQLClient:
    """
    PostgreSQL client tailored for exploit development needs.
    
    Features:
    - Connection management with automatic reconnection
    - Query execution with result processing
    - Transaction support
    - Error handling and logging
    - Parameterized queries for safety
    """
    
    def __init__(self,
                 host: str,
                 port: int = 5432,
                 database: str = "postgres",
                 username: str = "",
                 password: str = "",
                 timeout: int = 10,
                 verbose: bool = False):
        """
        Initialize PostgreSQL client
        
        Args:
            host: Database host
            port: Database port
            database: Database name
            username: Username for authentication
            password: Password for authentication
            timeout: Connection timeout
            verbose: Enable verbose logging
        """
        self.host = host
        self.port = port
        self.database = database
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verbose = verbose
        
        self.connection: Optional[psycopg2.extensions.connection] = None
        self.cursor: Optional[psycopg2.extensions.cursor] = None
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.PostgreSQLClient")
    
    def connect(self) -> bool:
        """
        Establish database connection
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            connection_params = {
                'host': self.host,
                'port': self.port,
                'database': self.database,
                'user': self.username,
                'password': self.password,
                'connect_timeout': self.timeout,
                'sslmode': 'prefer'  # Try SSL but don't require it
            }
            
            if self.verbose:
                self.logger.info(f"Connecting to PostgreSQL: {self.host}:{self.port}/{self.database}")
            
            self.connection = psycopg2.connect(**connection_params)
            self.cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            if self.verbose:
                self.logger.info("PostgreSQL connection established")
            
            return True
            
        except Exception as e:
            self.logger.error(f"PostgreSQL connection failed: {e}")
            return False
    
    def disconnect(self) -> None:
        """Close database connection and cleanup resources"""
        if self.cursor:
            self.cursor.close()
            self.cursor = None
        
        if self.connection:
            self.connection.close()
            self.connection = None
        
        if self.verbose:
            self.logger.info("PostgreSQL connection closed")
    
    def is_connected(self) -> bool:
        """Check if connection is active"""
        try:
            if self.connection and self.cursor:
                self.cursor.execute("SELECT 1")
                return True
        except:
            pass
        return False
    
    def reconnect(self) -> bool:
        """Reconnect to database"""
        self.disconnect()
        return self.connect()
    
    def execute_query(self, query: str, params: Optional[Tuple] = None, fetch: bool = True) -> Dict[str, Any]:
        """
        Execute a SQL query
        
        Args:
            query: SQL query string
            params: Query parameters for parameterized queries
            fetch: Whether to fetch results
            
        Returns:
            Dictionary with query results and metadata
        """
        if not self.connection or not self.cursor:
            raise RuntimeError("Not connected to PostgreSQL server")
        
        try:
            if self.verbose:
                self.logger.info(f"Executing query: {query[:100]}...")
                if params:
                    self.logger.debug(f"Parameters: {params}")
            
            # Execute query
            self.cursor.execute(query, params)
            
            result = {
                'success': True,
                'rowcount': self.cursor.rowcount,
                'description': self.cursor.description,
                'rows': []
            }
            
            # Fetch results if requested and available
            if fetch and self.cursor.description:
                result['rows'] = self.cursor.fetchall()
            
            # Commit if not in transaction
            if self.connection.autocommit:
                self.connection.commit()
            
            if self.verbose:
                self.logger.info(f"Query executed successfully, {result['rowcount']} rows affected")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Query execution failed: {e}")
            # Rollback on error
            if self.connection:
                self.connection.rollback()
            
            return {
                'success': False,
                'error': str(e),
                'rowcount': 0,
                'rows': []
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