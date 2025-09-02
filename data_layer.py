# Data Layer - Database Access and Data Persistence
# This file contains database operations that may be vulnerable to injection attacks
# Demonstrates: SQL injection vulnerabilities, parameterized queries, ORM usage

import sqlite3
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Database connection and basic operations"""

    def __init__(self, db_path="demo_app.db"):
        self.db_path = db_path
        self._initialize_db()

    def _initialize_db(self):
        """Initialize database with sample data"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_date TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create products table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    price REAL DEFAULT 0.0
                )
            ''')

            # Insert sample data
            cursor.execute("INSERT OR IGNORE INTO users (id, name, email, role) VALUES (1, 'John Doe', 'john@example.com', 'user')")
            cursor.execute("INSERT OR IGNORE INTO users (id, name, email, role) VALUES (2, 'Admin User', 'admin@example.com', 'admin')")
            cursor.execute("INSERT OR IGNORE INTO products (id, name, description, price) VALUES (1, 'Laptop', 'Gaming laptop', 999.99)")

            conn.commit()

    def execute_query(self, query, params=None):
        """Execute raw SQL query - VULNERABLE TO INJECTION"""
        logger.info(f"Executing query: {query}")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            try:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)

                results = cursor.fetchall()
                column_names = [description[0] for description in cursor.description] if cursor.description else []

                return {
                    "success": True,
                    "data": [dict(zip(column_names, row)) for row in results],
                    "row_count": len(results)
                }
            except Exception as e:
                logger.error(f"Database error: {e}")
                return {
                    "success": False,
                    "error": str(e)
                }

class UserRepository:
    """User data access layer"""

    def __init__(self):
        self.db = DatabaseManager()

    def search_users_by_name(self, search_pattern):
        """VULNERABLE: Direct string concatenation in SQL"""
        # This is the classic SQL injection vulnerability
        query = f"SELECT id, name, email, role, created_date FROM users WHERE name LIKE '{search_pattern}'"

        logger.info(f"Searching users with pattern: {search_pattern}")
        return self.db.execute_query(query)

    def get_user_by_id(self, user_id_condition):
        """VULNERABLE: Direct string concatenation"""
        # Another SQL injection vulnerability
        query = f"SELECT id, name, email, role, created_date FROM users {user_id_condition}"

        logger.info(f"Getting user with condition: {user_id_condition}")
        return self.db.execute_query(query)

    def get_user_permissions(self, user_id):
        """SECURE: Parameterized query"""
        query = "SELECT role, permissions FROM users WHERE id = ?"
        return self.db.execute_query(query, (user_id,))

    def get_user_activity(self, user_id):
        """SECURE: Parameterized query"""
        query = "SELECT action, timestamp FROM user_activity WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10"
        return self.db.execute_query(query, (user_id,))

    def delete_user(self, user_id):
        """SECURE: Parameterized query"""
        query = "DELETE FROM users WHERE id = ?"
        return self.db.execute_query(query, (user_id,))

    def promote_user_to_admin(self, user_id):
        """SECURE: Parameterized query"""
        query = "UPDATE users SET role = 'admin' WHERE id = ?"
        return self.db.execute_query(query, (user_id,))

    def demote_user_from_admin(self, user_id):
        """SECURE: Parameterized query"""
        query = "UPDATE users SET role = 'user' WHERE id = ?"
        return self.db.execute_query(query, (user_id,))

class ProductRepository:
    """Product data access layer"""

    def __init__(self):
        self.db = DatabaseManager()

    def search_products(self, search_term):
        """SECURE: Parameterized query with proper LIKE syntax"""
        query = "SELECT id, name, description, price FROM products WHERE name LIKE ? OR description LIKE ?"
        search_pattern = f"%{search_term}%"
        return self.db.execute_query(query, (search_pattern, search_pattern))

class AuditLogger:
    """Audit logging for security events"""

    def __init__(self):
        self.db = DatabaseManager()

    def log_security_event(self, event_type, details, user_id=None):
        """Log security events to database"""
        query = """
        INSERT INTO security_audit (event_type, details, user_id, timestamp)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """
        return self.db.execute_query(query, (event_type, str(details), user_id))

    def get_security_events(self, user_id=None, limit=100):
        """Get security events"""
        if user_id:
            query = "SELECT * FROM security_audit WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?"
            return self.db.execute_query(query, (user_id, limit))
        else:
            query = "SELECT * FROM security_audit ORDER BY timestamp DESC LIMIT ?"
            return self.db.execute_query(query, (limit,))

class SecureDatabaseManager:
    """Secure database operations using parameterized queries"""

    def __init__(self):
        self.db = DatabaseManager()

    def safe_user_search(self, search_term, user_id=None):
        """SECURE: Completely safe user search"""
        if user_id:
            query = "SELECT id, name, email, role FROM users WHERE id = ?"
            return self.db.execute_query(query, (user_id,))
        else:
            query = "SELECT id, name, email, role FROM users WHERE name LIKE ?"
            search_pattern = f"%{search_term}%"
            return self.db.execute_query(query, (search_pattern,))
