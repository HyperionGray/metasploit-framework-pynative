#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit Framework Database Manager - Python Native Version

This script manages the Metasploit Framework database using native Python
implementation with PostgreSQL.
"""

import sys
import os
import argparse
import subprocess
import time
import shutil
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required for database configuration")
    print("Install it with: pip install PyYAML")
    sys.exit(1)


class MsfDatabase:
    """Python implementation of Metasploit Database Manager"""
    
    def __init__(self):
        self.db_name = 'msf'
        self.db_user = 'msf'
        self.db_password = 'msf'
        self.db_host = '127.0.0.1'
        self.db_port = 5432
        self.config_dir = Path.home() / '.msf4'
        self.db_config = self.config_dir / 'database.yml'
        
    def _check_postgres_installed(self):
        """Check if PostgreSQL is installed"""
        try:
            return shutil.which('psql') is not None
        except Exception:
            return False
            
    def _check_postgres_running(self):
        """Check if PostgreSQL server is running"""
        try:
            result = subprocess.run(['pg_isready', '-h', self.db_host, '-p', str(self.db_port)],
                                   capture_output=True,
                                   text=True,
                                   timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
            
    def _check_database_exists(self):
        """Check if MSF database exists"""
        try:
            result = subprocess.run(['psql', '-h', self.db_host, '-p', str(self.db_port),
                                   '-U', self.db_user, '-lqt'],
                                   capture_output=True,
                                   text=True,
                                   env={**os.environ, 'PGPASSWORD': self.db_password},
                                   timeout=5)
            return self.db_name in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
            
    def _create_config(self):
        """Create database configuration file"""
        self.config_dir.mkdir(exist_ok=True, parents=True)
        
        config = {
            'development': {
                'adapter': 'postgresql',
                'database': self.db_name,
                'username': self.db_user,
                'password': self.db_password,
                'host': self.db_host,
                'port': self.db_port,
                'pool': 200,
            },
            'production': {
                'adapter': 'postgresql',
                'database': self.db_name,
                'username': self.db_user,
                'password': self.db_password,
                'host': self.db_host,
                'port': self.db_port,
                'pool': 200,
            },
            'test': {
                'adapter': 'postgresql',
                'database': 'msftest',
                'username': 'msftest',
                'password': 'msftest',
                'host': self.db_host,
                'port': self.db_port,
                'pool': 200,
            }
        }
        
        with open(self.db_config, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
            
        print(f"[+] Database configuration written to {self.db_config}")
        
    def status(self):
        """Check database status"""
        print("[*] Checking database status...")
        
        if not self._check_postgres_installed():
            print("[-] PostgreSQL is not installed")
            print("[*] Install PostgreSQL first:")
            print("    Ubuntu/Debian: sudo apt-get install postgresql")
            print("    CentOS/RHEL:   sudo yum install postgresql-server")
            print("    macOS:         brew install postgresql")
            return False
        
        print("[+] PostgreSQL is installed")
        
        if not self._check_postgres_running():
            print("[-] PostgreSQL server is not running")
            print("[*] Start PostgreSQL with: sudo systemctl start postgresql")
            return False
            
        print("[+] PostgreSQL server is running")
        
        if not self.db_config.exists():
            print("[-] Database configuration not found")
            print("[*] Initialize database with: ./msfdb.py init")
            return False
            
        print("[+] Database configuration exists")
        
        if self._check_database_exists():
            print("[+] MSF database exists and is accessible")
            print(f"[*] Database: {self.db_name}")
            print(f"[*] User: {self.db_user}")
            print(f"[*] Host: {self.db_host}:{self.db_port}")
            return True
        else:
            print("[-] MSF database does not exist or is not accessible")
            print("[*] Initialize database with: ./msfdb.py init")
            return False
        
    def init(self):
        """Initialize database"""
        print("[*] Initializing Metasploit Framework database...")
        
        if not self._check_postgres_installed():
            print("[-] PostgreSQL is not installed")
            print("[*] Install PostgreSQL first")
            return False
            
        if not self._check_postgres_running():
            print("[-] PostgreSQL server is not running")
            print("[*] Start PostgreSQL service first")
            return False
        
        # Create configuration
        self._create_config()
        
        # Note: Actual database creation would require superuser privileges
        print("[*] Database configuration created")
        print("[!] Note: Database user and database creation requires PostgreSQL superuser")
        print("[*] To complete setup, run as postgres user:")
        print(f"    sudo -u postgres createuser {self.db_user}")
        print(f"    sudo -u postgres createdb -O {self.db_user} {self.db_name}")
        print(f"    sudo -u postgres psql -c \"ALTER USER {self.db_user} WITH PASSWORD '{self.db_password}'\"")
        
        return True
        
    def start(self):
        """Start database"""
        print("[*] Starting PostgreSQL...")
        print("[!] Note: Starting PostgreSQL requires appropriate system permissions")
        print("[*] Please start PostgreSQL manually using one of these commands:")
        print("    sudo systemctl start postgresql   # For systemd-based systems")
        print("    sudo service postgresql start     # For SysV-based systems")
        print("    brew services start postgresql    # For macOS with Homebrew")
        return False
        
    def stop(self):
        """Stop database"""
        print("[*] Stopping PostgreSQL...")
        print("[!] Note: Stopping PostgreSQL requires appropriate system permissions")
        print("[*] Please stop PostgreSQL manually using one of these commands:")
        print("    sudo systemctl stop postgresql   # For systemd-based systems")
        print("    sudo service postgresql stop     # For SysV-based systems")
        print("    brew services stop postgresql    # For macOS with Homebrew")
        return False
        
    def restart(self):
        """Restart database"""
        print("[*] Restarting PostgreSQL...")
        self.stop()
        time.sleep(2)
        self.start()
        
    def delete(self):
        """Delete database configuration and data"""
        print("[*] Deleting Metasploit database...")
        
        # Remove config file
        if self.db_config.exists():
            self.db_config.unlink()
            print(f"[+] Removed database configuration: {self.db_config}")
        
        print("[!] Note: This only removes the configuration file")
        print("[*] To remove the database itself, run:")
        print(f"    sudo -u postgres dropdb {self.db_name}")
        print(f"    sudo -u postgres dropuser {self.db_user}")


def main():
    """Main entry point for msfdb."""
    
    parser = argparse.ArgumentParser(
        description='Metasploit Framework Database Manager - Python Native'
    )
    parser.add_argument('command', 
                       choices=['init', 'start', 'stop', 'restart', 'status', 'delete'],
                       help='Database command to execute')
    parser.add_argument('--component', 
                       choices=['database', 'webservice', 'all'], 
                       default='database',
                       help='Component to manage (currently only database supported)')
    parser.add_argument('-q', '--quiet', 
                       action='store_true',
                       help='Suppress banner')
    
    args = parser.parse_args()
    
    # Show banner
    if not args.quiet:
        print("\n" + "="*70)
        print("  Metasploit Framework Database Manager")
        print("  Python Native Implementation")
        print("="*70 + "\n")
    
    # Create database manager
    db_manager = MsfDatabase()
    
    # Execute command
    try:
        if args.command == 'init':
            db_manager.init()
        elif args.command == 'start':
            db_manager.start()
        elif args.command == 'stop':
            db_manager.stop()
        elif args.command == 'restart':
            db_manager.restart()
        elif args.command == 'status':
            db_manager.status()
        elif args.command == 'delete':
            db_manager.delete()
            
    except KeyboardInterrupt:
        print("\n[*] Operation cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Aborted")
        sys.exit(1)
