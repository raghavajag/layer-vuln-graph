# Data Layer - Database Access and Data Persistence
# This file contains database operations that may be vulnerable to injection attacks
# Demonstrates: SQL injection vulnerabilities, parameterized queries, ORM usage

import sqlite3
import logging
import os
import subprocess
from typing import List, Dict, Any, Optional

try:
    from flask import render_template_string
except ImportError:
    # Fallback for when Flask is not available
    def render_template_string(template):
        return template

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
            
            # Create user profiles table for XSS testing
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_profiles (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL,
                    badge TEXT DEFAULT 'New User',
                    title TEXT DEFAULT '',
                    description TEXT DEFAULT ''
                )
            ''')
            
            # Create user activity table for reporting
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_activity (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Insert sample data
            cursor.execute("INSERT OR IGNORE INTO users (id, name, email, role) VALUES (1, 'John Doe', 'john@example.com', 'user')")
            cursor.execute("INSERT OR IGNORE INTO users (id, name, email, role) VALUES (2, 'Admin User', 'admin@example.com', 'admin')")
            cursor.execute("INSERT OR IGNORE INTO products (id, name, description, price) VALUES (1, 'Laptop', 'Gaming laptop', 999.99)")
            
            # Insert sample profile data for XSS testing
            cursor.execute("INSERT OR IGNORE INTO user_profiles (id, username, badge, title, description) VALUES (1, 'john_doe', 'Verified', 'Software Engineer', 'Experienced developer')")
            cursor.execute("INSERT OR IGNORE INTO user_profiles (id, username, badge, title, description) VALUES (2, 'admin_user', 'Admin', 'System Administrator', 'Full system access')")
            
            # Insert sample activity data for report testing
            cursor.execute("INSERT OR IGNORE INTO user_activity (id, user_id, action) VALUES (1, 1, 'login')")
            cursor.execute("INSERT OR IGNORE INTO user_activity (id, user_id, action) VALUES (2, 1, 'view_profile')")
            cursor.execute("INSERT OR IGNORE INTO user_activity (id, user_id, action) VALUES (3, 2, 'admin_login')")

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
    
    def get_profile_enhancements(self, username):
        """Get profile enhancement data - VULNERABLE XSS SINK"""
        # VULNERABLE: Direct string concatenation for XSS testing
        query = f"SELECT badge, title, description FROM user_profiles WHERE username = '{username}'"
        
        logger.info(f"Getting profile enhancements for: {username}")
        result = self.db.execute_query(query)
        
        # Return processed data that could contain XSS
        if result.get("success") and result.get("data"):
            return result["data"][0] if result["data"] else {}
        else:
            return {"badge": "New User", "title": "", "description": ""}
    
    def complex_search_with_dynamic_query(self, search_query, filter_type, sort_order, limit):
        """VULNERABLE: Complex dynamic SQL construction"""
        # Build complex dynamic query - MULTIPLE INJECTION POINTS
        base_query = "SELECT id, name, email, role, created_date FROM users"
        
        # WHERE clause construction - VULNERABLE
        where_clause = f"WHERE name LIKE '{search_query}'"
        
        if filter_type == "email":
            where_clause = f"WHERE email LIKE '{search_query}'"
        elif filter_type == "advanced":
            # Advanced filter allows complex conditions - VERY VULNERABLE
            where_clause = f"WHERE {search_query}"
        
        # ORDER BY clause - VULNERABLE
        order_clause = f"ORDER BY {sort_order}"
        
        # LIMIT clause - VULNERABLE
        limit_clause = f"LIMIT {limit}"
        
        # Combine all parts - ULTIMATE VULNERABILITY
        full_query = f"{base_query} {where_clause} {order_clause} {limit_clause}"
        
        logger.info(f"Executing complex search query: {full_query}")
        return self.db.execute_query(full_query)
    
    def generate_dynamic_report(self, report_type, date_condition, user_filter, group_clause, custom_filter):
        """VULNERABLE: Dynamic report generation with multiple injection points"""

        # Build dynamic query based on report type
        if report_type == "user_activity":
            base_query = "SELECT user_id, action, COUNT(*) as count FROM user_activity"
        elif report_type == "user_stats":
            base_query = "SELECT role, COUNT(*) as count, AVG(id) as avg_id FROM users"
        else:
            # VULNERABLE: Uses report_type directly in query
            base_query = f"SELECT * FROM {report_type}"

        # WHERE clause with multiple vulnerable conditions
        where_parts = []

        if date_condition:
            where_parts.append(date_condition)

        if user_filter and user_filter != "1=1":
            where_parts.append(user_filter)

        if custom_filter:
            # MOST VULNERABLE: Direct custom filter injection
            where_parts.append(custom_filter)

        where_clause = ""
        if where_parts:
            where_clause = f"WHERE {' AND '.join(where_parts)}"

        # Complete query construction
        full_query = f"{base_query} {where_clause} {group_clause}"

        logger.info(f"Executing dynamic report query: {full_query}")
        return self.db.execute_query(full_query)

    # ============ NEW CRITICAL VULNERABLE METHODS ============
    # Based on the provided vulnerable codebase patterns

    def execute_raw_sql(self, query):
        """CRITICAL: Execute raw SQL query - VULNERABLE TO INJECTION"""
        logger.info(f"Executing raw SQL: {query}")
        
        # VULNERABLE: Direct SQL execution without any validation
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                results = cursor.fetchall()
                
                # Return results with password hashes - INFORMATION DISCLOSURE
                formatted_results = []
                for row in results:
                    if len(row) >= 3:
                        formatted_results.append({
                            'username': row[0] if len(row) > 0 else '',
                            'email': row[1] if len(row) > 1 else '',
                            'password_hash': row[2] if len(row) > 2 else ''
                        })
                    else:
                        formatted_results.append({"data": row})
                
                return {"users": formatted_results}
        except Exception as e:
            return {"error": str(e), "query": query}

    def execute_system_command_via_subprocess(self, user_cmd):
        """CRITICAL: System command execution - DIRECT RCE"""
        logger.info(f"Executing system command via subprocess: {user_cmd}")
        
        # VULNERABLE: Direct command execution with shell=True
        import subprocess
        result = subprocess.run(user_cmd, shell=True, capture_output=True, text=True)
        
        return {
            "command": user_cmd,
            "output": result.stdout,
            "error": result.stderr,
            "return_code": result.returncode
        }

    def write_file_to_system(self, filename, content):
        """CRITICAL: File write operations - PATH TRAVERSAL + RCE"""
        logger.info(f"Writing file to system: {filename}")
        
        # VULNERABLE: No path validation allows traversal
        file_path = f"/uploads/{filename}"
        
        try:
            # Create directory if it doesn't exist (dangerous with traversal)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Write file without validation
            with open(file_path, 'w') as f:
                f.write(content)
            
            return f"File saved to {file_path}"
        except Exception as e:
            return {"error": str(e), "attempted_path": file_path}

    def render_unsafe_template(self, template_data, user_data):
        """CRITICAL: Template rendering - SERVER-SIDE TEMPLATE INJECTION"""
        logger.info(f"Rendering unsafe template")
        
        # VULNERABLE: Direct template rendering with user input
        template = f"""
        <div class="user-content">
            <h1>User Generated Content</h1>
            <p>Template: {template_data}</p>
            <p>User Data: {user_data}</p>
        </div>
        """
        
        # VULNERABLE: Template injection
        return render_template_string(template)

    def execute_debug_query(self, table_name, debug_query):
        """HIGH: Debug database operations - SQL INJECTION"""
        logger.info(f"Executing debug query on table: {table_name}")
        
        # VULNERABLE: Multiple injection points
        if debug_query:
            full_query = f"SELECT * FROM {table_name} WHERE {debug_query}"
        else:
            full_query = f"SELECT COUNT(*) FROM {table_name}"
        
        logger.info(f"Debug query: {full_query}")
        return self.execute_query(full_query)

    def read_file_with_custom_encoding(self, filepath, encoding):
        """HIGH: File read operations - PATH TRAVERSAL"""
        logger.info(f"Reading file with custom encoding: {filepath}, encoding: {encoding}")
        
        # VULNERABLE: Path traversal
        full_path = f"/internal_docs/{filepath}"
        
        try:
            # VULNERABLE: Missing encoding parameter validation
            with open(full_path, 'r', encoding=encoding) as f:
                content = f.read()
            return {"content": content, "path": full_path}
        except Exception as e:
            return {"error": str(e), "attempted_path": full_path}

    def write_to_application_log(self, log_message, log_level):
        """MEDIUM: Log operations - LOG INJECTION"""
        logger.info(f"Writing to application log: {log_level}")
        
        # VULNERABLE: Log injection
        log_entry = f"[{log_level.upper()}] {log_message}"
        
        try:
            # Write to log file without sanitization
            with open("/var/log/application.log", "a") as log_file:
                log_file.write(log_entry + "\n")
            return {"status": "logged", "entry": log_entry}
        except Exception as e:
            return {"error": str(e), "attempted_log": log_entry}

    def execute_script_with_shell(self, script_name, args):
        """MEDIUM: Script execution - COMMAND INJECTION"""
        logger.info(f"Executing script with shell: {script_name}")
        
        # VULNERABLE: Shell command injection
        import subprocess
        command = f"{script_name} {args}"
        
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        return {
            "script": script_name,
            "args": args,
            "command": command,
            "output": result.stdout,
            "error": result.stderr
        }

    def read_internal_system_file(self, filename):
        """HIGH: Internal file access - PATH TRAVERSAL"""
        logger.info(f"Reading internal system file: {filename}")
        
        # VULNERABLE: Path traversal to system files
        file_path = f"/internal_system/{filename}"
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            return {"content": content, "file": filename}
        except Exception as e:
            return {"error": str(e), "attempted_file": filename}

    def execute_custom_sanitized_query(self, sanitized_filter):
        """HIGH: Custom sanitization - BYPASSABLE SANITIZATION"""
        logger.info(f"Executing custom sanitized query")
        
        # VULNERABLE: Custom sanitization can be bypassed
        query = f"SELECT * FROM products WHERE description = '{sanitized_filter}'"
        
        logger.info(f"Custom sanitized query: {query}")
        return self.execute_query(query)


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
