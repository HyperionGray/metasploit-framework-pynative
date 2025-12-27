#!/usr/bin/env python3
"""
bish-please: Smart Shell Navigation Tool
A frecency-based directory jumping tool with visual prompt integration
"""

import os
import sys
import sqlite3
import argparse
import time
from pathlib import Path
from typing import List, Tuple, Optional


class BishDB:
    """Database manager for bish-please"""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize database connection"""
        if db_path is None:
            # Use .bish.sqlite in the metasploit root or home directory
            msf_root = os.environ.get('MSF_ROOT')
            if msf_root:
                db_path = os.path.join(msf_root, '.bish.sqlite')
            else:
                # Fallback to home directory for predictable location
                db_path = os.path.join(os.path.expanduser('~'), '.bish.sqlite')
        
        self.db_path = db_path
        self.conn = None
        self._init_db()
    
    def _init_db(self):
        """Initialize database connection and ensure tables exist"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        
        # Ensure tables exist with proper schema
        self._create_tables()
        
        # Migrate/upgrade schema if needed
        self._upgrade_schema()
    
    def _create_tables(self):
        """Create database tables"""
        cursor = self.conn.cursor()
        
        # bjump_locations table for directory bookmarks
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bjump_locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alias TEXT NOT NULL UNIQUE,
                path TEXT NOT NULL,
                location_type TEXT NOT NULL DEFAULT 'directory',
                source_file TEXT NOT NULL,
                indexed_time INTEGER NOT NULL
            )
        ''')
        
        # indexed_entries for frecency tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS indexed_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                full_path TEXT NOT NULL,
                is_directory INTEGER NOT NULL DEFAULT 0,
                is_hidden INTEGER NOT NULL DEFAULT 0,
                size INTEGER NOT NULL DEFAULT 0,
                mtime INTEGER NOT NULL,
                indexed_time INTEGER NOT NULL,
                visit_count INTEGER NOT NULL DEFAULT 1,
                last_access INTEGER NOT NULL,
                frecency_score REAL NOT NULL DEFAULT 1.0
            )
        ''')
        
        # index_metadata for configuration
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS index_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        
        # Create indices for performance
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_path ON indexed_entries(path)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_full_path_unique ON indexed_entries(full_path)
        ''')
        
        self.conn.commit()
    
    def _upgrade_schema(self):
        """Upgrade database schema by adding missing columns"""
        cursor = self.conn.cursor()
        
        # Check if indexed_entries table needs migration
        cursor.execute("PRAGMA table_info(indexed_entries)")
        columns = {row[1] for row in cursor.fetchall()}
        
        # Add missing columns if they don't exist
        if 'visit_count' not in columns:
            try:
                cursor.execute('ALTER TABLE indexed_entries ADD COLUMN visit_count INTEGER NOT NULL DEFAULT 1')
            except sqlite3.OperationalError:
                pass  # Column already exists
        
        if 'last_access' not in columns:
            try:
                cursor.execute('ALTER TABLE indexed_entries ADD COLUMN last_access INTEGER NOT NULL DEFAULT 0')
                # Set last_access to indexed_time for existing rows
                cursor.execute('UPDATE indexed_entries SET last_access = indexed_time WHERE last_access = 0')
            except sqlite3.OperationalError:
                pass  # Column already exists
        
        if 'frecency_score' not in columns:
            try:
                cursor.execute('ALTER TABLE indexed_entries ADD COLUMN frecency_score REAL NOT NULL DEFAULT 1.0')
            except sqlite3.OperationalError:
                pass  # Column already exists
        
        # Create frecency index after column exists
        try:
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_frecency ON indexed_entries(frecency_score DESC)')
        except sqlite3.OperationalError:
            pass  # Index already exists or column doesn't exist
        
        self.conn.commit()
    
    def add_bjump(self, alias: str, path: str, source_file: str = 'manual'):
        """Add a bookmark/jump location"""
        path = os.path.abspath(os.path.expanduser(path))
        
        if not os.path.isdir(path):
            raise ValueError(f"Path does not exist or is not a directory: {path}")
        
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO bjump_locations 
            (alias, path, location_type, source_file, indexed_time)
            VALUES (?, ?, 'directory', ?, ?)
        ''', (alias, path, source_file, int(time.time())))
        
        self.conn.commit()
        return True
    
    def remove_bjump(self, alias: str):
        """Remove a bookmark/jump location"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM bjump_locations WHERE alias = ?', (alias,))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def get_bjump(self, alias: str) -> Optional[str]:
        """Get path for a bookmark alias"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT path FROM bjump_locations WHERE alias = ?', (alias,))
        row = cursor.fetchone()
        return row['path'] if row else None
    
    def list_bjumps(self) -> List[Tuple[str, str]]:
        """List all bookmarks"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT alias, path FROM bjump_locations ORDER BY alias')
        return [(row['alias'], row['path']) for row in cursor.fetchall()]
    
    def record_visit(self, path: str):
        """Record a directory visit for frecency calculation"""
        path = os.path.abspath(path)
        current_time = int(time.time())
        is_directory = 1  # Mark as directory
        
        cursor = self.conn.cursor()
        
        # Check if entry exists
        cursor.execute('SELECT id, visit_count, frecency_score FROM indexed_entries WHERE full_path = ?', (path,))
        row = cursor.fetchone()
        
        if row:
            # Update existing entry
            visit_count = row['visit_count'] + 1
            old_score = row['frecency_score']
            
            # Calculate new frecency score
            # Frecency = frequency * recency
            # Recent visits get higher weight
            time_weight = 1.0  # Full weight for current visit
            new_score = old_score * 0.9 + time_weight  # Decay old score, add new visit
            
            cursor.execute('''
                UPDATE indexed_entries 
                SET visit_count = ?, last_access = ?, frecency_score = ?
                WHERE id = ?
            ''', (visit_count, current_time, new_score, row['id']))
        else:
            # Create new entry
            try:
                stat = os.stat(path)
                is_hidden = os.path.basename(path).startswith('.')
                
                cursor.execute('''
                    INSERT INTO indexed_entries 
                    (path, full_path, is_directory, is_hidden, size, mtime, indexed_time, visit_count, last_access, frecency_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 1.0)
                ''', (os.path.basename(path), path, is_directory, is_hidden, stat.st_size, int(stat.st_mtime), current_time, current_time))
            except OSError:
                pass  # Ignore errors for non-existent paths
        
        self.conn.commit()
    
    def search_directories(self, query: str, limit: int = 10) -> List[Tuple[str, float]]:
        """Search directories by path using frecency scoring"""
        cursor = self.conn.cursor()
        
        # First, check for exact bjump alias match
        exact_match = self.get_bjump(query)
        if exact_match and os.path.isdir(exact_match):
            return [(exact_match, 100.0)]
        
        # Search indexed directories
        query_pattern = f'%{query}%'
        cursor.execute('''
            SELECT full_path, frecency_score 
            FROM indexed_entries 
            WHERE is_directory = 1 AND full_path LIKE ?
            ORDER BY frecency_score DESC, last_access DESC
            LIMIT ?
        ''', (query_pattern, limit))
        
        results = [(row['full_path'], row['frecency_score']) for row in cursor.fetchall()]
        
        # If no results, do a filesystem scan
        if not results:
            results = self._filesystem_search(query, limit)
        
        return results
    
    def _filesystem_search(self, query: str, limit: int = 10) -> List[Tuple[str, float]]:
        """Fallback filesystem search when no indexed results"""
        results = []
        search_paths = [
            os.path.expanduser('~'),
            os.environ.get('MSF_ROOT', os.getcwd()),
            '/tmp',
            '/opt',
        ]
        
        for search_root in search_paths:
            if not os.path.isdir(search_root):
                continue
            
            try:
                for root, dirs, _ in os.walk(search_root):
                    # Don't descend into hidden directories or too deep
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    
                    if query.lower() in root.lower():
                        results.append((root, 0.5))  # Low score for unvisited
                    
                    if len(results) >= limit:
                        break
                
                if len(results) >= limit:
                    break
            except PermissionError:
                continue
        
        return results[:limit]
    
    def cleanup_old_entries(self, days: int = 90):
        """Remove entries not accessed in N days"""
        cutoff_time = int(time.time()) - (days * 24 * 60 * 60)
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM indexed_entries WHERE last_access < ?', (cutoff_time,))
        deleted = cursor.rowcount
        self.conn.commit()
        return deleted
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


def cmd_bjump(args, db: BishDB):
    """Handle bjump command"""
    if args.list:
        # List all bookmarks
        bjumps = db.list_bjumps()
        if not bjumps:
            print("No bookmarks defined. Use 'bish add <alias> <path>' to create one.")
            return 1
        
        print("Bookmarks:")
        for alias, path in bjumps:
            exists = "✓" if os.path.isdir(path) else "✗"
            print(f"  {exists} {alias:20s} -> {path}")
        return 0
    
    if args.alias:
        # Jump to bookmarked location
        path = db.get_bjump(args.alias)
        if path:
            if os.path.isdir(path):
                # Output path for shell to cd to
                print(path)
                db.record_visit(path)
                return 0
            else:
                print(f"Error: Bookmarked path no longer exists: {path}", file=sys.stderr)
                return 1
        else:
            # Try fuzzy search
            results = db.search_directories(args.alias, limit=1)
            if results:
                print(results[0][0])
                db.record_visit(results[0][0])
                return 0
            else:
                print(f"Error: No bookmark or directory found for: {args.alias}", file=sys.stderr)
                return 1
    
    print("Usage: bish bjump <alias> or bish bjump --list")
    return 1


def cmd_add(args, db: BishDB):
    """Add a bookmark"""
    if not args.alias or not args.path:
        print("Usage: bish add <alias> <path>")
        return 1
    
    try:
        db.add_bjump(args.alias, args.path)
        print(f"Bookmark added: {args.alias} -> {args.path}")
        return 0
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_remove(args, db: BishDB):
    """Remove a bookmark"""
    if not args.alias:
        print("Usage: bish remove <alias>")
        return 1
    
    if db.remove_bjump(args.alias):
        print(f"Bookmark removed: {args.alias}")
        return 0
    else:
        print(f"Error: Bookmark not found: {args.alias}", file=sys.stderr)
        return 1


def cmd_search(args, db: BishDB):
    """Search directories"""
    if not args.query:
        print("Usage: bish search <query>")
        return 1
    
    results = db.search_directories(args.query, limit=args.limit or 10)
    
    if not results:
        print(f"No directories found matching: {args.query}")
        return 1
    
    print(f"Directories matching '{args.query}':")
    for i, (path, score) in enumerate(results, 1):
        print(f"  {i}. {path} (score: {score:.2f})")
    
    return 0


def cmd_visit(args, db: BishDB):
    """Record a directory visit (used by shell hook)"""
    if args.path:
        path = os.path.abspath(os.path.expanduser(args.path))
        if os.path.isdir(path):
            db.record_visit(path)
            return 0
    return 1


def cmd_cleanup(args, db: BishDB):
    """Clean up old entries"""
    days = args.days or 90
    deleted = db.cleanup_old_entries(days)
    print(f"Cleaned up {deleted} entries older than {days} days")
    return 0


def cmd_stats(args, db: BishDB):
    """Show statistics"""
    cursor = db.conn.cursor()
    
    cursor.execute('SELECT COUNT(*) as count FROM bjump_locations')
    bjump_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM indexed_entries WHERE is_directory = 1')
    dir_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT SUM(visit_count) as total FROM indexed_entries')
    visit_count = cursor.fetchone()['total'] or 0
    
    cursor.execute('SELECT full_path, frecency_score FROM indexed_entries ORDER BY frecency_score DESC LIMIT 5')
    top_dirs = cursor.fetchall()
    
    print("Bish Statistics:")
    print(f"  Bookmarks: {bjump_count}")
    print(f"  Indexed directories: {dir_count}")
    print(f"  Total visits: {visit_count}")
    print()
    print("Top 5 directories by frecency:")
    for i, row in enumerate(top_dirs, 1):
        print(f"  {i}. {row['full_path']} (score: {row['frecency_score']:.2f})")
    
    return 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        prog='bish',
        description='Smart shell navigation with frecency-based directory jumping'
    )
    
    parser.add_argument('--db', help='Path to database file')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # bjump command
    bjump_parser = subparsers.add_parser('bjump', help='Jump to bookmarked directory')
    bjump_parser.add_argument('alias', nargs='?', help='Bookmark alias or search term')
    bjump_parser.add_argument('-l', '--list', action='store_true', help='List all bookmarks')
    
    # add command
    add_parser = subparsers.add_parser('add', help='Add bookmark')
    add_parser.add_argument('alias', help='Bookmark alias')
    add_parser.add_argument('path', help='Directory path')
    
    # remove command
    remove_parser = subparsers.add_parser('remove', help='Remove bookmark')
    remove_parser.add_argument('alias', help='Bookmark alias')
    
    # search command
    search_parser = subparsers.add_parser('search', help='Search directories')
    search_parser.add_argument('query', help='Search query')
    search_parser.add_argument('-l', '--limit', type=int, help='Max results')
    
    # visit command (internal)
    visit_parser = subparsers.add_parser('visit', help='Record visit (internal)')
    visit_parser.add_argument('path', help='Directory path')
    
    # cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean old entries')
    cleanup_parser.add_argument('-d', '--days', type=int, help='Remove entries older than N days')
    
    # stats command
    stats_parser = subparsers.add_parser('stats', help='Show statistics')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Initialize database
    db = BishDB(args.db)
    
    try:
        # Dispatch to command handler
        if args.command == 'bjump':
            return cmd_bjump(args, db)
        elif args.command == 'add':
            return cmd_add(args, db)
        elif args.command == 'remove':
            return cmd_remove(args, db)
        elif args.command == 'search':
            return cmd_search(args, db)
        elif args.command == 'visit':
            return cmd_visit(args, db)
        elif args.command == 'cleanup':
            return cmd_cleanup(args, db)
        elif args.command == 'stats':
            return cmd_stats(args, db)
        else:
            parser.print_help()
            return 1
    finally:
        db.close()


if __name__ == '__main__':
    sys.exit(main())
