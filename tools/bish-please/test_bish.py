#!/usr/bin/env python3
"""
Test suite for bish-please functionality
"""

import os
import sys
import tempfile
import shutil
import sqlite3
from pathlib import Path

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from bish import BishDB


def test_database_creation():
    """Test database creation and schema"""
    print("Testing database creation...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, 'test.db')
        db = BishDB(db_path)
        
        # Check tables exist
        cursor = db.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        
        assert 'bjump_locations' in tables, "bjump_locations table not created"
        assert 'indexed_entries' in tables, "indexed_entries table not created"
        assert 'index_metadata' in tables, "index_metadata table not created"
        
        db.close()
        print("✓ Database creation test passed")


def test_bookmark_operations():
    """Test bookmark add, get, remove, list"""
    print("Testing bookmark operations...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, 'test.db')
        db = BishDB(db_path)
        
        # Create test directories
        test_dir1 = os.path.join(tmpdir, 'dir1')
        test_dir2 = os.path.join(tmpdir, 'dir2')
        os.makedirs(test_dir1)
        os.makedirs(test_dir2)
        
        # Test add
        db.add_bjump('test1', test_dir1)
        db.add_bjump('test2', test_dir2)
        
        # Test get
        path1 = db.get_bjump('test1')
        assert path1 == test_dir1, f"Expected {test_dir1}, got {path1}"
        
        # Test list
        bjumps = db.list_bjumps()
        assert len(bjumps) == 2, f"Expected 2 bookmarks, got {len(bjumps)}"
        
        # Test remove
        removed = db.remove_bjump('test1')
        assert removed, "Failed to remove bookmark"
        
        path1 = db.get_bjump('test1')
        assert path1 is None, "Bookmark not removed"
        
        db.close()
        print("✓ Bookmark operations test passed")


def test_visit_tracking():
    """Test directory visit tracking and frecency"""
    print("Testing visit tracking...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, 'test.db')
        db = BishDB(db_path)
        
        # Create test directory
        test_dir = os.path.join(tmpdir, 'testdir')
        os.makedirs(test_dir)
        
        # Record multiple visits
        for _ in range(5):
            db.record_visit(test_dir)
        
        # Check visit count
        cursor = db.conn.cursor()
        cursor.execute('SELECT visit_count, frecency_score FROM indexed_entries WHERE full_path = ?', (test_dir,))
        row = cursor.fetchone()
        
        assert row is not None, "Visit not recorded"
        assert row[0] == 5, f"Expected 5 visits, got {row[0]}"
        assert row[1] > 1.0, f"Expected frecency_score > 1.0, got {row[1]}"
        
        db.close()
        print("✓ Visit tracking test passed")


def test_search():
    """Test directory search functionality"""
    print("Testing search...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, 'test.db')
        db = BishDB(db_path)
        
        # Create test directories
        test_dirs = [
            os.path.join(tmpdir, 'project1'),
            os.path.join(tmpdir, 'project2'),
            os.path.join(tmpdir, 'other'),
        ]
        for d in test_dirs:
            os.makedirs(d)
            db.record_visit(d)
        
        # Search for 'project'
        results = db.search_directories('project')
        assert len(results) >= 2, f"Expected at least 2 results, got {len(results)}"
        
        # Check that project directories are in results
        result_paths = [r[0] for r in results]
        assert test_dirs[0] in result_paths, "project1 not in search results"
        assert test_dirs[1] in result_paths, "project2 not in search results"
        
        db.close()
        print("✓ Search test passed")


def test_cleanup():
    """Test cleanup of old entries"""
    print("Testing cleanup...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, 'test.db')
        db = BishDB(db_path)
        
        # Create test directory and record visit
        test_dir = os.path.join(tmpdir, 'testdir')
        os.makedirs(test_dir)
        db.record_visit(test_dir)
        
        # Manually set last_access to old date (100 days ago)
        import time
        old_time = int(time.time()) - (100 * 24 * 60 * 60)
        cursor = db.conn.cursor()
        cursor.execute('UPDATE indexed_entries SET last_access = ? WHERE full_path = ?', (old_time, test_dir))
        db.conn.commit()
        
        # Run cleanup (90 days)
        deleted = db.cleanup_old_entries(days=90)
        assert deleted >= 1, f"Expected at least 1 deletion, got {deleted}"
        
        # Verify entry was removed
        cursor.execute('SELECT COUNT(*) FROM indexed_entries WHERE full_path = ?', (test_dir,))
        count = cursor.fetchone()[0]
        assert count == 0, "Old entry not removed"
        
        db.close()
        print("✓ Cleanup test passed")


def test_schema_upgrade():
    """Test schema upgrade from old database"""
    print("Testing schema upgrade...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, 'test.db')
        
        # Create old-style database without new columns
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE indexed_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                full_path TEXT NOT NULL,
                is_directory INTEGER NOT NULL DEFAULT 0,
                is_hidden INTEGER NOT NULL DEFAULT 0,
                size INTEGER NOT NULL DEFAULT 0,
                mtime INTEGER NOT NULL,
                indexed_time INTEGER NOT NULL
            )
        ''')
        cursor.execute('''
            INSERT INTO indexed_entries (path, full_path, is_directory, is_hidden, size, mtime, indexed_time)
            VALUES ('test', '/tmp/test', 1, 0, 0, 0, 0)
        ''')
        conn.commit()
        conn.close()
        
        # Open with BishDB to trigger upgrade
        db = BishDB(db_path)
        
        # Check that new columns exist
        cursor = db.conn.cursor()
        cursor.execute("PRAGMA table_info(indexed_entries)")
        columns = {row[1] for row in cursor.fetchall()}
        
        assert 'visit_count' in columns, "visit_count column not added"
        assert 'last_access' in columns, "last_access column not added"
        assert 'frecency_score' in columns, "frecency_score column not added"
        
        db.close()
        print("✓ Schema upgrade test passed")


def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("Running bish-please test suite")
    print("=" * 60)
    print()
    
    tests = [
        test_database_creation,
        test_bookmark_operations,
        test_visit_tracking,
        test_search,
        test_cleanup,
        test_schema_upgrade,
    ]
    
    failed = 0
    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"✗ {test.__name__} FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
        print()
    
    print("=" * 60)
    if failed == 0:
        print("✓ All tests passed!")
        return 0
    else:
        print(f"✗ {failed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(run_all_tests())
