# Database Layer (Layer: Sink 🧪)
import sqlite3
import logging
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Database manager - Sink Layer"""
    
    def __init__(self, db_path: str = "demo_app.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with demo tables"""
        with self.get_connection() as conn:
            # Create users table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create comments table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    post_id INTEGER,
                    content TEXT NOT NULL,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Create profiles table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY,
                    user_name TEXT NOT NULL,
                    content TEXT,
                    is_public BOOLEAN DEFAULT 1
                )
            ''')
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Get database connection with context manager"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

def search_users_in_database(search_query: str) -> List[Dict[str, Any]]:
    """
    Search users in database - Sink function
    VULNERABLE: Direct SQL injection via string concatenation
    """
    logger.info(f"Searching users with query: {search_query}")
    
    db_manager = DatabaseManager()
    
    # VULNERABILITY: Direct string concatenation in SQL query
    vulnerable_sql = f"""
        SELECT id, name, email, role, created_date 
        FROM users 
        WHERE name LIKE '%{search_query}%' 
           OR email LIKE '%{search_query}%'
        ORDER BY name
    """
    
    logger.debug(f"Executing SQL: {vulnerable_sql}")
    
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.execute(vulnerable_sql)
            results = [dict(row) for row in cursor.fetchall()]
            
        logger.info(f"Found {len(results)} users matching query")
        return results
        
    except sqlite3.Error as e:
        logger.error(f"Database error during user search: {e}")
        return []

def fetch_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch user by ID - Sink function  
    VULNERABLE: SQL injection via user_id parameter
    """
    logger.info(f"Fetching user by ID: {user_id}")
    
    db_manager = DatabaseManager()
    
    # VULNERABILITY: Direct insertion of user_id into SQL
    vulnerable_sql = f"""
        SELECT id, name, email, role, created_date 
        FROM users 
        WHERE id = {user_id}
    """
    
    logger.debug(f"Executing SQL: {vulnerable_sql}")
    
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.execute(vulnerable_sql)
            result = cursor.fetchone()
            
        if result:
            user_data = dict(result)
            logger.info(f"Found user: {user_data['name']}")
            return user_data
        else:
            logger.info("User not found")
            return None
            
    except sqlite3.Error as e:
        logger.error(f"Database error during user fetch: {e}")
        return None

def get_profile_content(profile_name: str) -> str:
    """
    Get profile content - Sink function
    VULNERABLE: SQL injection + reflected content (XSS)
    """
    logger.info(f"Getting profile content for: {profile_name}")
    
    db_manager = DatabaseManager()
    
    # VULNERABILITY: SQL injection via profile name
    vulnerable_sql = f"""
        SELECT content 
        FROM profiles 
        WHERE user_name = '{profile_name}' 
          AND is_public = 1
    """
    
    logger.debug(f"Executing SQL: {vulnerable_sql}")
    
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.execute(vulnerable_sql)
            result = cursor.fetchone()
            
        if result:
            # VULNERABILITY: Raw content returned (potential XSS)
            content = result['content']
            logger.info("Profile content found")
            return content
        else:
            # VULNERABILITY: Reflected input in default content
            default_content = f"""
            <div class="default-profile">
                <h3>Welcome to {profile_name}'s profile!</h3>
                <p>This user hasn't set up their profile yet.</p>
                <script>
                    // Profile analytics
                    console.log('Viewing profile: {profile_name}');
                </script>
            </div>
            """
            logger.info("Using default profile content")
            return default_content
            
    except sqlite3.Error as e:
        logger.error(f"Database error during profile fetch: {e}")
        return f"<p>Error loading profile for {profile_name}</p>"

def store_comment(comment_data: Dict[str, Any]) -> Optional[int]:
    """
    Store comment in database - Sink function
    VULNERABLE: SQL injection via comment content
    """
    logger.info(f"Storing comment for user {comment_data.get('user_id')}")
    
    db_manager = DatabaseManager()
    
    # Extract data
    content = comment_data.get('processed_content', comment_data.get('text', ''))
    user_id = comment_data.get('user_id', 0)
    post_id = comment_data.get('post_id', 0)
    
    # VULNERABILITY: Direct string insertion in SQL
    vulnerable_sql = f"""
        INSERT INTO comments (user_id, post_id, content)
        VALUES ({user_id}, {post_id}, '{content}')
    """
    
    logger.debug(f"Executing SQL: {vulnerable_sql}")
    
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.execute(vulnerable_sql)
            comment_id = cursor.lastrowid
            conn.commit()
            
        logger.info(f"Comment stored with ID: {comment_id}")
        return comment_id
        
    except sqlite3.Error as e:
        logger.error(f"Database error during comment storage: {e}")
        return None

def fetch_admin_notes(user_id: str) -> List[str]:
    """
    Fetch admin notes for user - Sink function
    VULNERABLE: SQL injection via user_id
    """
    logger.info(f"Fetching admin notes for user: {user_id}")
    
    db_manager = DatabaseManager()
    
    # VULNERABILITY: SQL injection in admin context (high privilege)
    vulnerable_sql = f"""
        SELECT note_text, created_by, created_date
        FROM admin_notes 
        WHERE user_id = {user_id}
        ORDER BY created_date DESC
    """
    
    try:
        with db_manager.get_connection() as conn:
            # Create admin_notes table if not exists
            conn.execute('''
                CREATE TABLE IF NOT EXISTS admin_notes (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    note_text TEXT,
                    created_by INTEGER,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor = conn.execute(vulnerable_sql)
            notes = [row['note_text'] for row in cursor.fetchall()]
            
        logger.info(f"Found {len(notes)} admin notes")
        return notes
        
    except sqlite3.Error as e:
        logger.error(f"Database error during admin notes fetch: {e}")
        return []

def fetch_user_access_logs(user_id: str) -> List[Dict[str, Any]]:
    """
    Fetch user access logs - Sink function
    VULNERABLE: SQL injection in security-sensitive context
    """
    logger.info(f"Fetching access logs for user: {user_id}")
    
    db_manager = DatabaseManager()
    
    # VULNERABILITY: SQL injection accessing security logs
    vulnerable_sql = f"""
        SELECT access_time, ip_address, user_agent, action
        FROM access_logs 
        WHERE user_id = {user_id}
        ORDER BY access_time DESC
        LIMIT 50
    """
    
    try:
        with db_manager.get_connection() as conn:
            # Create access_logs table if not exists
            conn.execute('''
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    action TEXT
                )
            ''')
            
            cursor = conn.execute(vulnerable_sql)
            logs = [dict(row) for row in cursor.fetchall()]
            
        logger.info(f"Found {len(logs)} access log entries")
        return logs
        
    except sqlite3.Error as e:
        logger.error(f"Database error during access logs fetch: {e}")
        return []

def get_user_reputation(user_id: int) -> float:
    """
    Get user reputation score - Sink function
    VULNERABLE: SQL injection via user_id (used in calculations)
    """
    logger.info(f"Getting reputation for user: {user_id}")
    
    db_manager = DatabaseManager()
    
    # VULNERABILITY: SQL injection affecting reputation calculation
    vulnerable_sql = f"""
        SELECT 
            COUNT(c.id) as comment_count,
            AVG(CASE WHEN c.content LIKE '%good%' THEN 5 ELSE 1 END) as avg_score
        FROM comments c 
        WHERE c.user_id = {user_id}
    """
    
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.execute(vulnerable_sql)
            result = cursor.fetchone()
            
        if result:
            comment_count = result['comment_count'] or 0
            avg_score = result['avg_score'] or 1.0
            reputation = min(comment_count * avg_score, 100.0)
            
            logger.info(f"User reputation calculated: {reputation}")
            return reputation
        
        return 0.0
        
    except sqlite3.Error as e:
        logger.error(f"Database error during reputation calculation: {e}")
        return 0.0