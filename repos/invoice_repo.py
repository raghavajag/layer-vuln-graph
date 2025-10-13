import sqlite3
import logging

logger = logging.getLogger(__name__)

# Simulated database connection for demonstration
def get_db_connection():
    """Get database connection"""
    try:
        return sqlite3.connect('invoices.db')
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return None

# ==================== VULNERABLE SQL INJECTION PATTERNS ====================

def repo_get_invoice_by_id(user_id):
    """CRITICAL: Direct SQL injection - no protection"""
    query = f"SELECT * FROM invoices WHERE id = {user_id}"
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        logger.info(f"Executing query: {query}")  # Also logging sensitive query
        return cursor.execute(query)
    return None

def authenticate_user(username, password):
    """GOOD TO FIX: SQL injection with partial protection"""
    # Some attempt at sanitization but still vulnerable
    username = username.replace("'", "''")
    
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    # Still vulnerable to injection through password parameter
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    logger.info(f"Executing authentication query: {query}")  # Logging query (security issue)
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user

def search_invoices_vulnerable(search_term):
    """CRITICAL: SQL injection in public search - immediately exploitable"""
    conn = get_db_connection()
    if not conn:
        return []
    
    cursor = conn.cursor()
    # Direct string interpolation with user input
    query = f"SELECT * FROM invoices WHERE description LIKE '%{search_term}%'"
    cursor.execute(query)
    
    results = []
    for row in cursor.fetchall():
        results.append({
            'invoice_id': row[0],
            'user_id': row[1],
            'amount': row[2],
            'description': row[3]
        })
    
    conn.close()
    return results

def get_user_by_username_sqli(username):
    """CRITICAL: SQL injection exposing sensitive data"""
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username LIKE '%{username}%'"
    cursor.execute(query)
    
    results = []
    for row in cursor.fetchall():
        results.append({
            'username': row[0],
            'email': row[1],
            'password_hash': row[2],  # Exposing password hashes
            'role': row[3]
        })
    
    conn.close()
    return results

def search_logs_sqli(search_term):
    """GOOD TO FIX: SQL injection in logging system - lower business impact"""
    conn = get_db_connection()
    if not conn:
        return []
    
    cursor = conn.cursor()
    query = f"SELECT * FROM application_logs WHERE message LIKE '%{search_term}%'"
    cursor.execute(query)
    
    logs = []
    for row in cursor.fetchall():
        logs.append({
            'timestamp': row[0],
            'level': row[1],
            'message': row[2]
        })
    
    conn.close()
    return logs

def custom_sanitization_sqli(user_input):
    """GOOD TO FIX: Custom sanitization that might not be sufficient"""
    def custom_sql_escape(value):
        if not value:
            return ""
        # Incomplete sanitization
        return value.replace("'", "''").replace(";", "").replace("--", "")
    
    conn = get_db_connection()
    if not conn:
        return []
    
    safe_input = custom_sql_escape(user_input)
    cursor = conn.cursor()
    query = f"SELECT * FROM invoices WHERE description = '{safe_input}'"
    cursor.execute(query)
    
    return cursor.fetchall()

# ==================== PROTECTED/SANITIZED PATTERNS (FALSE POSITIVES) ====================

def search_with_parameterized_query(search_term):
    """PROTECTED: SQL injection properly sanitized with parameterized query"""
    conn = get_db_connection()
    if not conn:
        return []
    
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM invoices WHERE description LIKE ?", [f"%{search_term}%"])
    results = cursor.fetchall()
    conn.close()
    return results

def get_invoice_secure(invoice_id):
    """PROTECTED: Properly parameterized query"""
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
    result = cursor.fetchone()
    conn.close()
    return result

# ==================== DEAD CODE WITH VULNERABILITIES ====================

def unused_sql_injection_function():
    """DEAD CODE: This function is never called - should be classified as dead code"""
    from flask import request
    user_input = request.args.get('query')
    
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()

def legacy_db_query_vulnerable(table_name):
    """DEAD CODE: Unused function with table name injection"""
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    query = f"SELECT COUNT(*) FROM {table_name}"
    cursor.execute(query)
    return cursor.fetchone()[0]

def deprecated_admin_query(admin_password):
    """DEAD CODE: Unused admin function with hardcoded credentials"""
    # Hardcoded credentials in dead code
    if admin_password == "admin123":
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "SELECT * FROM admin_logs"
        cursor.execute(query)
        return cursor.fetchall()
    return None
