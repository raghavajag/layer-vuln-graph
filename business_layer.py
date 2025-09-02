# Business Layer - Core Business Logic
# This file contains business logic that processes data from API layer
# Demonstrates: Data transformation, business rules, multiple call paths

import logging
import os
import subprocess
import sqlite3
from flask import render_template_string
from .security_layer import InputValidator, SQLInjectionDetector
from .data_layer import DatabaseManager, UserRepository, ProductRepository
from .security_layer import AuthenticationManager

logger = logging.getLogger(__name__)

class UserService:
    """User management business logic"""

    def __init__(self):
        self.validator = InputValidator()
        self.sql_detector = SQLInjectionDetector()
        self.db_manager = DatabaseManager()
        self.user_repo = UserRepository()
        self.auth_manager = AuthenticationManager()

    def search_users(self, search_query, user_id):
        """Complex user search with multiple paths"""
        logger.info(f"Searching users with query: {search_query}, user_id: {user_id}")

        # Path 1: Search by query (vulnerable path)
        if search_query:
            return self._search_by_query(search_query)

        # Path 2: Search by user ID (also vulnerable)
        elif user_id:
            return self._search_by_user_id(user_id)

        return {"error": "No search criteria provided"}

    def _search_by_query(self, query):
        """Search users by query - VULNERABLE PATH"""
        # Business logic processing
        processed_query = self._preprocess_search_query(query)

        # Weak security check (false positive detection opportunity)
        if self.sql_detector.detect_sql_injection_patterns(processed_query):
            logger.warning(f"Potential SQL injection detected in query: {processed_query}")
            # But still processes the request! (ineffective control)

        # Call data layer
        return self.user_repo.search_users_by_name(processed_query)

    def _search_by_user_id(self, user_id):
        """Search by user ID - ALSO VULNERABLE"""
        processed_id = self._preprocess_user_id(user_id)
        
        # Weak validation
        if not processed_id.isdigit():
            logger.warning("Non-numeric user ID provided")
            # Still processes non-numeric IDs - vulnerability

        return self.user_repo.get_user_by_id(processed_id)

    def _preprocess_search_query(self, query):
        """Preprocess search query - INSUFFICIENT SANITIZATION"""
        # Remove obvious SQL injection attempts (easily bypassed)
        cleaned = query.replace("DROP TABLE", "").replace("DELETE FROM", "")
        return cleaned

    def _preprocess_user_id(self, user_id):
        """Preprocess user ID - VULNERABLE"""
        # Basic processing that doesn't prevent injection
        return user_id.strip()

    def get_user_details(self, user_id, is_admin=False):
        """Get user details - COMPLEX AUTHORIZATION BYPASS"""
        # Weak authorization check
        if is_admin:
            # Admin path (still vulnerable to injection)
            return self.user_repo.get_admin_user_details(user_id)
        else:
            # Regular user path
            return self.user_repo.get_user_details(user_id)

    def admin_user_management(self, action, user_id):
        """Admin user management - AUTHORIZATION + INJECTION"""
        logger.info(f"Admin action: {action} on user: {user_id}")

        if action == "delete":
            return self.user_repo.delete_user(user_id)
        elif action == "promote":
            return self.user_repo.promote_user(user_id)
        elif action == "view":
            return self.user_repo.view_user_sensitive_data(user_id)
        else:
            return {"error": "Unknown action"}

    def process_user_profile(self, username, profile_type):
        """Process user profile - COMPLEX XSS CALL CHAIN"""
        # Business logic processing that creates vulnerability path
        logger.info(f"Processing profile for user: {username}, type: {profile_type}")

        # Call security layer for "validation" (ineffective)
        if not self.validator.is_safe_search_term(username):
            # Weak control: logs but continues processing
            logger.warning(f"Suspicious username detected: {username}")

        # Process through multiple business logic steps
        processed_name = self._enhance_display_name(username, profile_type)

        # Call data layer to get additional profile data
        profile_data = self.user_repo.get_profile_enhancements(processed_name)

        return {
            "display_name": processed_name,
            "profile_data": profile_data
        }

    def _enhance_display_name(self, username, profile_type):
        """Enhance display name based on profile type - VULNERABLE PROCESSING"""
        if profile_type == "premium":
            # Add premium badge without encoding
            return f"⭐ {username}"
        elif profile_type == "admin":
            # Add admin indicator 
            return f"🔧 Admin: {username}"
        else:
            return username

    def complex_user_search(self, query, filter_type, sort_order, limit):
        """Complex user search - MULTI-LAYER SQL INJECTION PATH"""
        logger.info(f"Complex search: query={query}, filter={filter_type}, sort={sort_order}, limit={limit}")

        # Step 1: Business logic preprocessing
        processed_query = self._preprocess_complex_query(query, filter_type)

        # Step 2: Security validation (ineffective)
        if self.sql_detector.detect_sql_injection_patterns(processed_query):
            logger.warning(f"SQL injection detected but continuing: {processed_query}")
            # Logs warning but continues processing - VULNERABLE CONTROL

        # Step 3: Sort order processing (vulnerable)
        validated_sort = self._process_sort_order(sort_order)

        # Step 4: Limit processing (vulnerable)
        processed_limit = self._process_limit_parameter(limit)

        # Step 5: Call data layer with processed parameters
        return self.user_repo.complex_search_with_dynamic_query(
            processed_query, filter_type, validated_sort, processed_limit
        )

    def _preprocess_complex_query(self, query, filter_type):
        """Preprocess complex query - VULNERABLE LOGIC"""
        if filter_type == "name":
            return f"name LIKE '%{query}%'"
        elif filter_type == "email":
            return f"email = '{query}'"
        elif filter_type == "id":
            return f"id = {query}"
        else:
            # VULNERABLE: Uses filter_type directly
            return f"{filter_type} = '{query}'"

    def _process_sort_order(self, sort_order):
        """Process sort order - VULNERABLE TO INJECTION"""
        valid_orders = ["asc", "desc"]
        if sort_order.lower() in valid_orders:
            return f"name {sort_order.upper()}"
        else:
            # VULNERABLE: Uses raw input if not in valid list
            return f"name {sort_order}"

    def _process_limit_parameter(self, limit):
        """Process limit parameter - VULNERABLE VALIDATION"""
        try:
            limit_int = int(limit)
            if limit_int > 100:
                limit_int = 100
            return str(limit_int)
        except ValueError:
            # VULNERABLE: Returns original string if not a number
            logger.warning(f"Invalid limit parameter: {limit}")
            return limit  # This could contain SQL injection

    def generate_advanced_report(self, report_type, date_range, user_filter, group_by, custom_filter):
        """Generate advanced report - COMPLEX SQL INJECTION THROUGH MULTIPLE PATHS"""
        logger.info(f"Generating report: type={report_type}, range={date_range}, filter={user_filter}")

        # Business logic preprocessing
        processed_filter = self._process_report_filter(user_filter, custom_filter)
        date_condition = self._build_date_condition(date_range)
        group_clause = self._build_group_by_clause(group_by)

        # Multiple validation layers (all bypassable)
        if custom_filter and self.sql_detector.detect_sql_injection_patterns(custom_filter):
            logger.warning("Suspicious custom filter detected")
            # But still processes it - INEFFECTIVE CONTROL

        # Call data layer with complex parameters
        return self.user_repo.generate_dynamic_report(
            report_type=report_type,
            date_condition=date_condition,
            user_filter=processed_filter,
            group_clause=group_clause,
            custom_filter=custom_filter
        )

    def _process_report_filter(self, user_filter, custom_filter):
        """Process report filter - VULNERABLE LOGIC"""
        if custom_filter:
            # VULNERABLE: Combines filters without proper validation
            return f"{user_filter} AND {custom_filter}"
        else:
            # Simple filter processing
            return f"user_id = {user_filter}"  # VULNERABLE: No parameterization

    def _build_date_condition(self, date_range):
        """Build date condition - VULNERABLE TO INJECTION"""
        try:
            days = int(date_range)
            return f"created_date >= DATE('now', '-{days} days')"
        except ValueError:
            # VULNERABLE: Uses raw input if not a number
            return f"created_date >= {date_range}"

    def _build_group_by_clause(self, group_by):
        """Build GROUP BY clause - VULNERABLE"""
        allowed_groups = ["date", "user", "action"]
        if group_by in allowed_groups:
            return f"GROUP BY {group_by}"
        else:
            # VULNERABLE: Uses raw input if not in allowed list
            return f"GROUP BY {group_by}"

    # ============ NEW CRITICAL VULNERABLE METHODS ============
    # Based on the provided vulnerable codebase patterns

    def execute_raw_search_query(self, search_term):
        """CRITICAL: Direct SQL injection - immediately exploitable"""
        logger.info(f"Executing raw search query: {search_term}")
        
        # VULNERABLE: Direct string concatenation in SQL query
        # This mimics the public_search_vulnerable pattern from the provided code
        query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%'"
        
        # Call data layer with vulnerable query
        return self.user_repo.execute_raw_sql(query)

    def execute_system_command(self, user_cmd):
        """CRITICAL: Command injection - no protections"""
        logger.info(f"Executing system command: {user_cmd}")
        
        # Weak "validation" that can be bypassed
        if "rm -rf" in user_cmd:
            logger.warning("Potentially dangerous command detected")
            # But still executes it - INEFFECTIVE CONTROL
        
        # VULNERABLE: Direct command execution through subprocess
        result = subprocess.run(user_cmd, shell=True, capture_output=True, text=True)
        
        return {
            "command": user_cmd,
            "output": result.stdout,
            "error": result.stderr,
            "return_code": result.returncode
        }

    def handle_file_operations(self, filename, content):
        """CRITICAL: Path traversal + RCE vulnerability"""
        logger.info(f"Handling file operation: {filename}")
        
        # Insufficient path validation
        if ".." in filename:
            logger.warning("Path traversal attempt detected")
            # Logs but continues - INEFFECTIVE CONTROL
        
        # VULNERABLE: Path traversal through business layer processing
        file_path = f"/uploads/{filename}"
        
        # Write file without proper validation
        with open(file_path, 'w') as f:
            f.write(content)
        
        return f"File saved to {file_path}"

    def render_dynamic_template(self, template_data, user_data):
        """CRITICAL: Server-side template injection"""
        logger.info(f"Rendering dynamic template with user data")
        
        # Weak template validation
        if "{{" in template_data:
            logger.warning("Template syntax detected")
            # Logs but continues - INEFFECTIVE CONTROL
        
        # VULNERABLE: Server-side template injection
        template = f"""
        <div class="dynamic-content">
            <h2>Dynamic Template</h2>
            <p>Template: {template_data}</p>
            <p>Data: {user_data}</p>
        </div>
        """
        
        # Render template with user input - VULNERABLE
        return render_template_string(template)

    def debug_database_operations(self, table_name, debug_query):
        """HIGH: SQL injection in database operations"""
        logger.info(f"Debug database operation: table={table_name}, query={debug_query}")
        
        # Weak validation
        if "DROP" in debug_query.upper():
            logger.warning("Potentially dangerous query detected")
            # Logs but continues - INEFFECTIVE CONTROL
        
        # VULNERABLE: Multiple injection points
        if table_name == "users":
            query = f"SELECT * FROM {table_name} WHERE {debug_query}"
        else:
            query = f"SELECT COUNT(*) FROM {table_name}"
        
        return self.user_repo.execute_raw_sql(query)

    def read_file_with_encoding(self, filepath, encoding):
        """HIGH: Path traversal in file operations"""
        logger.info(f"Reading file: {filepath} with encoding: {encoding}")
        
        # Insufficient path validation
        if filepath.startswith("/"):
            logger.warning("Absolute path detected")
            # Logs but continues - INEFFECTIVE CONTROL
        
        # VULNERABLE: File path traversal
        file_path = f"/internal_docs/{filepath}"
        
        try:
            # VULNERABLE: Missing encoding parameter validation
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
            return {"content": content}
        except Exception as e:
            return {"error": str(e)}

    def log_user_activity(self, log_message, log_level):
        """MEDIUM: Log injection and potential code execution"""
        logger.info(f"Logging user activity: {log_message} at level: {log_level}")
        
        # Weak log validation
        if "\n" in log_message:
            logger.warning("Newline detected in log message")
            # Logs but continues - INEFFECTIVE CONTROL
        
        # VULNERABLE: Log injection
        log_entry = f"{log_level.upper()}: {log_message}"
        
        # Write to log file without proper sanitization
        with open("/var/log/application.log", "a") as log_file:
            log_file.write(log_entry + "\n")
        
        return {"status": "logged", "message": log_entry}

    def execute_script_with_args(self, script_name, args):
        """MEDIUM: Subprocess injection with shell=True"""
        logger.info(f"Executing script: {script_name} with args: {args}")
        
        # Weak script validation
        if "/" in script_name:
            logger.warning("Path detected in script name")
            # Logs but continues - INEFFECTIVE CONTROL
        
        # VULNERABLE: Shell command injection
        command = f"{script_name} {args}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        return {
            "script": script_name,
            "args": args,
            "output": result.stdout,
            "error": result.stderr
        }

    def read_internal_file(self, filename):
        """HIGH: Path traversal - internal network only"""
        logger.info(f"Reading internal file: {filename}")
        
        # Weak internal file validation
        if filename.endswith(".conf"):
            logger.warning("Configuration file access detected")
            # Logs but continues - INEFFECTIVE CONTROL
        
        # VULNERABLE: Path traversal
        file_path = f"/internal_system/{filename}"
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            return {"content": content}
        except Exception as e:
            return {"error": str(e)}

    def custom_sanitized_query(self, table_filter):
        """HIGH: Custom SQL with insufficient sanitization"""
        logger.info(f"Custom sanitized query with filter: {table_filter}")
        
        # VULNERABLE: Custom sanitization that can be bypassed
        def custom_sql_escape(value):
            if not value:
                return ""
            # Weak custom sanitization that can be bypassed
            return value.replace("'", "''").replace(";", "").replace("--", "")
        
        safe_input = custom_sql_escape(table_filter)
        query = f"SELECT * FROM products WHERE description = '{safe_input}'"
        
        return self.user_repo.execute_raw_sql(query)


class ProductService:
    """Product-related business logic"""

    def __init__(self):
        self.product_repo = ProductRepository()
        self.validator = InputValidator()

    def search_products(self, search_term):
        """Search products - SECURE METHOD (demonstrates proper handling)"""
        logger.info(f"Searching products: {search_term}")

        # Proper validation and sanitization
        if not self.validator.is_safe_search_term(search_term):
            return {"error": "Invalid search term"}

        # Safe call to data layer with validated input
        return self.product_repo.search_products_secure(search_term)


class SearchService:
    """Generic search functionality"""

    def __init__(self):
        self.db_manager = DatabaseManager()

    def perform_search(self, search_type, query):
        """Generic search dispatcher"""
        if search_type == "users":
            return UserService().search_users(query, "")
        elif search_type == "products":
            return ProductService().search_products(query)
        else:
            return {"error": "Unknown search type"}