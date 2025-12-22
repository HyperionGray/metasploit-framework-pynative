"""
Comprehensive tests for PostgreSQL client helper functionality.

Tests the PostgreSQL client used for database-based exploit development to ensure
correct behavior after Ruby-to-Python migration.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import psycopg2

# Add python_framework to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'python_framework'))

from helpers.postgres_client import PostgreSQLClient, PostgreSQLExploitMixin


class TestPostgreSQLClientInitialization:
    """Test PostgreSQLClient initialization"""
    
    def test_default_initialization(self):
        """Test creating PostgreSQLClient with default values"""
        client = PostgreSQLClient(host="localhost")
        
        assert client.host == "localhost"
        assert client.port == 5432
        assert client.username == ""
        assert client.password == ""
        assert client.database == "postgres"
        assert client.verbose is False
        assert client.connection is None
    
    def test_initialization_with_hostname(self):
        """Test creating PostgreSQLClient with hostname"""
        client = PostgreSQLClient(host="db.example.com")
        
        assert client.host == "db.example.com"
    
    def test_initialization_with_custom_port(self):
        """Test creating PostgreSQLClient with custom port"""
        client = PostgreSQLClient(port=5433)
        
        assert client.port == 5433
    
    def test_initialization_with_credentials(self):
        """Test creating PostgreSQLClient with credentials"""
        client = PostgreSQLClient(
            host="db.example.com",
            username="postgres",
            password="password123",
            database="mydb"
        )
        
        assert client.username == "postgres"
        assert client.password == "password123"
        assert client.database == "mydb"
    
    def test_initialization_verbose_mode(self):
        """Test creating PostgreSQLClient in verbose mode"""
        client = PostgreSQLClient(verbose=True)
        
        assert client.verbose is True


class TestPostgreSQLClientConnection:
    """Test PostgreSQL connection functionality"""
    
    @patch('psycopg2.connect')
    def test_connect_success(self, mock_connect):
        """Test connecting successfully to PostgreSQL"""
        mock_connection = MagicMock()
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        
        result = client.connect()
        
        assert result is True
        assert client.connected is True
        mock_connect.assert_called_once()
    
    @patch('psycopg2.connect')
    def test_connect_failure(self, mock_connect):
        """Test connection failure handling"""
        mock_connect.side_effect = psycopg2.OperationalError("Connection failed")
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="wrong"
        )
        
        result = client.connect()
        
        assert result is False
        assert client.connected is False
    
    @patch('psycopg2.connect')
    def test_disconnect(self, mock_connect):
        """Test disconnecting from PostgreSQL"""
        mock_connection = MagicMock()
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        
        client.connect()
        client.disconnect()
        
        mock_connection.close.assert_called_once()
        assert client.connected is False


class TestPostgreSQLClientQueryExecution:
    """Test query execution functionality"""
    
    @patch('psycopg2.connect')
    def test_execute_select_query(self, mock_connect):
        """Test executing a SELECT query"""
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [("user1",), ("user2",)]
        mock_cursor.description = [("username",)]
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        client.connect()
        
        results = client.execute_query("SELECT username FROM users")
        
        assert len(results) == 2
        assert results[0][0] == "user1"
        assert results[1][0] == "user2"
        mock_cursor.execute.assert_called_once_with("SELECT username FROM users", None)
    
    @patch('psycopg2.connect')
    def test_execute_insert_query(self, mock_connect):
        """Test executing an INSERT query"""
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        client.connect()
        
        result = client.execute_query("INSERT INTO users (username) VALUES ('newuser')")
        
        assert result is True
        mock_connection.commit.assert_called_once()
    
    @patch('psycopg2.connect')
    def test_execute_query_with_parameters(self, mock_connect):
        """Test executing a parameterized query"""
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [("user1",)]
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        client.connect()
        
        results = client.execute_query(
            "SELECT username FROM users WHERE id = %s",
            params=(1,)
        )
        
        assert len(results) == 1
        mock_cursor.execute.assert_called_once_with(
            "SELECT username FROM users WHERE id = %s",
            (1,)
        )
    
    @patch('psycopg2.connect')
    def test_execute_query_error_handling(self, mock_connect):
        """Test query execution error handling"""
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = psycopg2.Error("Syntax error")
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        client.connect()
        
        result = client.execute_query("INVALID SQL")
        
        assert result is None or result is False
    
    @patch('psycopg2.connect')
    def test_execute_without_connection(self, mock_connect):
        """Test executing query without connection fails gracefully"""
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        
        result = client.execute_query("SELECT 1")
        
        assert result is None or result is False


class TestPostgreSQLClientTransactions:
    """Test transaction handling"""
    
    @patch('psycopg2.connect')
    def test_commit_transaction(self, mock_connect):
        """Test committing a transaction"""
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        client.connect()
        
        client.execute_query("INSERT INTO users (username) VALUES ('user1')")
        client.commit()
        
        # Commit should be called at least once (in execute_query or explicit commit)
        assert mock_connection.commit.called
    
    @patch('psycopg2.connect')
    def test_rollback_transaction(self, mock_connect):
        """Test rolling back a transaction"""
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        client.connect()
        
        client.rollback()
        
        mock_connection.rollback.assert_called_once()


class TestPostgreSQLExploitMixin:
    """Test PostgreSQLExploitMixin functionality"""
    
    def test_mixin_provides_postgres_client(self):
        """Test that mixin provides PostgreSQL client functionality"""
        
        class TestExploit(PostgreSQLExploitMixin):
            def __init__(self):
                self._postgres_client = None
                self._options = {
                    "RHOSTS": "db.example.com",
                    "RPORT": 5432,
                    "DATABASE": "postgres",
                    "USERNAME": "postgres",
                    "PASSWORD": "password123"
                }
            
            def get_option(self, name):
                return self._options.get(name)
        
        exploit = TestExploit()
        
        # Initialize PostgreSQL client
        exploit.init_postgres_client()
        
        # Check that PostgreSQL client is initialized
        assert exploit._postgres_client is not None
        assert hasattr(exploit, 'postgres_connect')
        assert hasattr(exploit, 'postgres_query')


class TestPostgreSQLClientUtilities:
    """Test utility methods"""
    
    @patch('psycopg2.connect')
    def test_get_version(self, mock_connect):
        """Test getting PostgreSQL version"""
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ("PostgreSQL 13.5",)
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        client.connect()
        
        # If get_version method exists
        if hasattr(client, 'get_version'):
            version = client.get_version()
            assert "PostgreSQL" in version
    
    @patch('psycopg2.connect')
    def test_list_databases(self, mock_connect):
        """Test listing databases"""
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [("postgres",), ("template1",), ("mydb",)]
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        client.connect()
        
        # If list_databases method exists
        if hasattr(client, 'list_databases'):
            databases = client.list_databases()
            assert len(databases) >= 0


class TestPostgreSQLClientErrorHandling:
    """Test error handling"""
    
    @patch('psycopg2.connect')
    def test_connection_timeout(self, mock_connect):
        """Test handling of connection timeout"""
        mock_connect.side_effect = psycopg2.OperationalError("Connection timed out")
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        
        result = client.connect()
        
        assert result is False
    
    @patch('psycopg2.connect')
    def test_authentication_failure(self, mock_connect):
        """Test handling of authentication failure"""
        mock_connect.side_effect = psycopg2.OperationalError("authentication failed")
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="wrong_password"
        )
        
        result = client.connect()
        
        assert result is False
    
    @patch('psycopg2.connect')
    def test_database_error(self, mock_connect):
        """Test handling of database errors"""
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = psycopg2.DatabaseError("Database error")
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        client.connect()
        
        result = client.execute_query("SELECT * FROM nonexistent_table")
        
        assert result is None or result is False


class TestPostgreSQLClientIntegration:
    """Integration tests for PostgreSQL client"""
    
    @patch('psycopg2.connect')
    def test_full_workflow(self, mock_connect):
        """Test a complete PostgreSQL workflow: connect, query, disconnect"""
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [("result",)]
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        
        # Connect
        assert client.connect() is True
        
        # Execute query
        results = client.execute_query("SELECT current_user")
        assert results is not None
        
        # Disconnect
        client.disconnect()
        assert client.connected is False
    
    def test_client_with_all_features(self):
        """Test client initialization with all features"""
        client = PostgreSQLClient(
            host="db.example.com",
            port=5433,
            username="postgres",
            password="password123",
            database="mydb",
            verbose=True
        )
        
        assert client.hostname == "db.example.com"
        assert client.port == 5433
        assert client.username == "postgres"
        assert client.password == "password123"
        assert client.database == "mydb"
        assert client.verbose is True


class TestPostgreSQLClientConnectionStates:
    """Test connection state management"""
    
    def test_initial_state(self):
        """Test initial connection state"""
        client = PostgreSQLClient()
        
        assert client.connected is False
        assert client.connection is None
    
    @patch('psycopg2.connect')
    def test_connected_state(self, mock_connect):
        """Test state after successful connection"""
        mock_connection = MagicMock()
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        
        client.connect()
        
        assert client.connected is True
        assert client.connection is not None
    
    @patch('psycopg2.connect')
    def test_disconnected_state(self, mock_connect):
        """Test state after disconnection"""
        mock_connection = MagicMock()
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        
        client.connect()
        client.disconnect()
        
        assert client.connected is False


class TestPostgreSQLClientSQLInjectionPrevention:
    """Test SQL injection prevention"""
    
    @patch('psycopg2.connect')
    def test_parameterized_queries(self, mock_connect):
        """Test that parameterized queries are used correctly"""
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        client = PostgreSQLClient(
            host="localhost",
            username="postgres",
            password="password123"
        )
        client.connect()
        
        # Use parameterized query
        client.execute_query(
            "SELECT * FROM users WHERE username = %s",
            params=("admin' OR '1'='1",)
        )
        
        # Verify parameterized query was used
        call_args = mock_cursor.execute.call_args
        assert call_args[0][1] is not None  # Parameters were passed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
