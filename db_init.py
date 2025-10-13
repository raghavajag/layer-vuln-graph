"""
Database Initialization Module
Contains database setup and various SQL operations with vulnerabilities
"""

import sqlite3
import logging
import os

logger = logging.getLogger(__name__)

# ==================== DATABASE INITIALIZATION ====================

def initialize_db():
    """Initialize the application databases"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
    conn.commit()
    conn.close()
    
    # Initialize invoice database
    conn = sqlite3.connect('invoices.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS invoices
                 (id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, 
                  description TEXT, status TEXT, created_at TEXT)''')
    conn.commit()
    conn.close()
    
    logger.info("Databases initialized successfully")

def setup_test_data():
    """Setup test data for development"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Insert test users with weak password hashing
    test_users = [
        ('admin', 'YWRtaW4xMjM=', 'admin'),  # base64 encoded 'admin123'
        ('user1', 'cGFzc3dvcmQ=', 'user'),   # base64 encoded 'password'
        ('testuser', 'dGVzdDEyMw==', 'user') # base64 encoded 'test123'
    ]
    
    try:
        c.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                      test_users)
        conn.commit()
        logger.info("Test data inserted successfully")
    except sqlite3.IntegrityError:
        logger.warning("Test data already exists")
    finally:
        conn.close()


# ==================== VULNERABLE DATABASE OPERATIONS ====================

def get_user_data_vulnerable(username):
    """CRITICAL: SQL injection vulnerability"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Direct string concatenation - SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    logger.info(f"Executing query: {query}")
    
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    
    return result

def search_users_by_role(role, username_filter=None):
    """CRITICAL: SQL injection through multiple parameters"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    if username_filter:
        # Vulnerable to injection through both parameters
        query = f"SELECT * FROM users WHERE role = '{role}' AND username LIKE '%{username_filter}%'"
    else:
        query = f"SELECT * FROM users WHERE role = '{role}'"
    
    logger.debug(f"Role search query: {query}")
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    
    return results

def execute_custom_query(table_name, condition):
    """CRITICAL: SQL injection - table name injection"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable to table name and condition injection
    query = f"SELECT * FROM {table_name} WHERE {condition}"
    logger.info(f"Custom query: {query}")
    
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    
    return results

def update_user_role_vulnerable(username, new_role):
    """GOOD TO FIX: SQL injection with partial sanitization"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Partial sanitization - still vulnerable
    username = username.replace("'", "''")
    
    # new_role parameter is not sanitized
    query = f"UPDATE users SET role = '{new_role}' WHERE username = '{username}'"
    logger.info(f"Update query: {query}")
    
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return {"success": True}

def delete_user_vulnerable(user_id):
    """GOOD TO FIX: SQL injection in delete operation"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Direct interpolation of user_id
    query = f"DELETE FROM users WHERE id = {user_id}"
    logger.warning(f"Delete query: {query}")
    
    cursor.execute(query)
    conn.commit()
    affected_rows = cursor.rowcount
    conn.close()
    
    return {"deleted": affected_rows}


# ==================== PROTECTED DATABASE OPERATIONS ====================

def get_user_data_secure(username):
    """PROTECTED: Parameterized query - no SQL injection"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Properly parameterized query
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    result = cursor.fetchall()
    conn.close()
    
    return result

def update_user_role_secure(username, new_role):
    """PROTECTED: Secure update with parameterized query"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Both parameters properly parameterized
    cursor.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, username))
    conn.commit()
    conn.close()
    
    return {"success": True}


# ==================== DEAD CODE WITH VULNERABILITIES ====================

def legacy_raw_query_executor(sql_query):
    """DEAD CODE: Never called - raw SQL execution"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Direct execution of arbitrary SQL
    cursor.execute(sql_query)
    results = cursor.fetchall()
    conn.close()
    
    return results

def unused_admin_query(admin_password):
    """DEAD CODE: Hardcoded credentials in unused function"""
    # Hardcoded admin password
    if admin_password == "SuperSecretAdminPass123!":
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE role = 'admin'")
        return cursor.fetchall()
    return None

def deprecated_batch_delete(user_ids_csv):
    """DEAD CODE: Unsafe batch operation"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable to injection through CSV list
    query = f"DELETE FROM users WHERE id IN ({user_ids_csv})"
    cursor.execute(query)
    conn.commit()
    conn.close()


# ==================== DATABASE UTILITY FUNCTIONS ====================

def check_db_exists():
    """Check if database files exist"""
    users_db = os.path.exists('users.db')
    invoices_db = os.path.exists('invoices.db')
    
    return {
        'users_db': users_db,
        'invoices_db': invoices_db,
        'both_exist': users_db and invoices_db
    }

def get_database_stats():
    """Get database statistics"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_users': user_count,
            'admin_users': admin_count,
            'regular_users': user_count - admin_count
        }
    except Exception as e:
        logger.error(f"Error getting database stats: {e}")
        return {"error": str(e)}


if __name__ == '__main__':
    # Initialize databases when run directly
    initialize_db()
    setup_test_data()
    print("Database initialization complete!")
    print(f"Database stats: {get_database_stats()}")
