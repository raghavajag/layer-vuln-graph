# API Layer - Entry Points for Attack Vectors
# This file contains various API endpoints that serve as entry points for attacks
# Demonstrates: Input validation, route handling, parameter processing

import os
import subprocess
import sqlite3
from flask import Flask, request, jsonify, render_template_string
from .business_layer import UserService, ProductService, SearchService
from .security_layer import InputValidator, AuthenticationManager
from .data_layer import DatabaseManager
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

class APIController:
    """Main API controller with multiple entry points"""

    def __init__(self):
        self.user_service = UserService()
        self.product_service = ProductService()
        self.search_service = SearchService()
        self.validator = InputValidator()
        self.auth_manager = AuthenticationManager()
        self.db_manager = DatabaseManager()

    def search_users_endpoint(self):
        """Entry point for user search - VULNERABLE PATH"""
        # This endpoint accepts user input and passes it through multiple layers
        search_query = request.args.get('q', '')
        user_id = request.args.get('user_id', '')

        # Basic input validation (insufficient)
        if not search_query and not user_id:
            return jsonify({"error": "Search query or user_id required"}), 400

        # Call business logic layer - this creates a complex call chain
        return self.user_service.search_users(search_query, user_id)

    def get_user_details_endpoint(self):
        """Admin endpoint for user details - PARTIALLY PROTECTED"""
        # This endpoint has authentication but still vulnerable
        auth_token = request.headers.get('Authorization', '')

        if not self.auth_manager.validate_token(auth_token):
            return jsonify({"error": "Unauthorized"}), 401

        user_id = request.args.get('id', '')
        return self.user_service.get_user_details(user_id, is_admin=True)

    def search_products_endpoint(self):
        """Product search with sanitization - SECURE PATH"""
        # This endpoint demonstrates proper input sanitization
        search_term = request.args.get('term', '')

        # Proper input validation and sanitization
        if not self.validator.is_safe_search_term(search_term):
            return jsonify({"error": "Invalid search term"}), 400

        # Sanitized input passed to business layer
        sanitized_term = self.validator.sanitize_html(search_term)
        return self.product_service.search_products(sanitized_term)

    def public_profile_endpoint(self):
        """Public profile display - COMPLEX XSS VULNERABLE WITH CALL CHAIN"""
        username = request.args.get('username', '')
        profile_type = request.args.get('type', 'basic')
        
        # Complex call chain: API -> Business -> Security -> Sink
        # This creates a multi-layer vulnerability path for testing
        processed_profile = self.user_service.process_user_profile(username, profile_type)
        
        # Direct output without encoding - VULNERABLE SINK
        return f"<h1>Welcome {processed_profile['display_name']}</h1>"

    def safe_profile_endpoint(self):
        """Safe profile with encoding - SECURE"""
        username = request.args.get('username', '')

        # Proper HTML encoding prevents XSS
        from html import escape
        safe_username = escape(username)
        return f"<h1>Welcome {safe_username}</h1>"
        
    def complex_user_search_endpoint(self):
        """Complex user search with multiple vulnerable call paths - SQL INJECTION"""
        # Entry point for complex SQL injection attack path
        search_query = request.args.get('query', '')
        filter_type = request.args.get('filter', 'name')
        sort_order = request.args.get('sort', 'asc')
        limit = request.args.get('limit', '10')
        
        # Complex call chain: API -> Business -> Multiple Security Checks -> Data Layer
        search_results = self.user_service.complex_user_search(
            query=search_query,
            filter_type=filter_type, 
            sort_order=sort_order,
            limit=limit
        )
        
        return jsonify(search_results)
    
    def advanced_report_endpoint(self):
        """Advanced reporting endpoint - COMPLEX SQL INJECTION THROUGH MULTIPLE LAYERS"""
        # Multiple input parameters creating complex attack surface
        report_type = request.args.get('report_type', 'user_activity')
        date_range = request.args.get('date_range', '30')
        user_filter = request.args.get('user_filter', '')
        group_by = request.args.get('group_by', 'date')
        custom_sql = request.args.get('custom_filter', '')  # DANGEROUS PARAMETER
        
        # Authentication check (bypassable through parameter manipulation)
        auth_token = request.headers.get('Authorization', '')
        if not self.auth_manager.validate_token(auth_token):
            # Weak security: allows bypass with specific parameters
            if not request.args.get('legacy_mode') == 'true':
                return jsonify({"error": "Unauthorized"}), 401
        
        # Complex vulnerable call chain
        report_data = self.user_service.generate_advanced_report(
            report_type=report_type,
            date_range=date_range,
            user_filter=user_filter,
            group_by=group_by,
            custom_filter=custom_sql
        )
        
        return jsonify(report_data)

    # ============ NEW CRITICAL VULNERABILITIES ============
    # Based on the provided vulnerable codebase patterns

    def public_search_critical(self):
        """CRITICAL: Direct SQL injection - immediately exploitable"""
        search_term = request.args.get('q', '')
        
        # VULNERABLE: Direct string concatenation in SQL query
        # This will create a detectable SQL injection vulnerability
        return self.user_service.execute_raw_search_query(search_term)

    def direct_command_execution(self):
        """CRITICAL: Command injection - no protections"""
        user_cmd = request.args.get('cmd', '')
        
        # VULNERABLE: Direct command execution through subprocess
        # Complex call chain: API -> Business -> System execution
        return self.user_service.execute_system_command(user_cmd)

    def file_upload_and_execute(self):
        """CRITICAL: Path traversal + RCE vulnerability"""
        filename = request.args.get('filename', '')
        content = request.args.get('content', '')
        
        # VULNERABLE: Path traversal through business layer
        return self.user_service.handle_file_operations(filename, content)

    def template_injection_endpoint(self):
        """CRITICAL: Server-side template injection"""
        template_data = request.args.get('template', '')
        user_data = request.args.get('data', '')
        
        # VULNERABLE: Template injection through business layer processing
        return self.user_service.render_dynamic_template(template_data, user_data)

    def database_debug_endpoint(self):
        """HIGH: SQL injection in database operations"""
        table_name = request.args.get('table', '')
        debug_query = request.args.get('query', '')
        
        # VULNERABLE: Multiple injection points
        return self.user_service.debug_database_operations(table_name, debug_query)

    def file_read_endpoint(self):
        """HIGH: Path traversal in file operations"""
        filepath = request.args.get('file', '')
        encoding = request.args.get('encoding', '')
        
        # VULNERABLE: File path traversal through multiple layers
        return self.user_service.read_file_with_encoding(filepath, encoding)

    def log_injection_endpoint(self):
        """MEDIUM: Log injection and potential code execution"""
        log_message = request.args.get('message', '')
        log_level = request.args.get('level', 'info')
        
        # VULNERABLE: Log injection through business layer
        return self.user_service.log_user_activity(log_message, log_level)

    def subprocess_endpoint(self):
        """MEDIUM: Subprocess injection with shell=True"""
        script_name = request.args.get('script', '')
        args = request.args.get('args', '')
        
        # VULNERABLE: Shell command injection
        return self.user_service.execute_script_with_args(script_name, args)

    def internal_file_read(self):
        """HIGH: Path traversal - internal network only"""
        filename = request.args.get('file', '')
        
        # VULNERABLE: Path traversal through business processing
        return self.user_service.read_internal_file(filename)

    def custom_sql_endpoint(self):
        """HIGH: Custom SQL with insufficient sanitization"""
        table_filter = request.args.get('filter', '')
        
        # VULNERABLE: Custom sanitization that can be bypassed
        return self.user_service.custom_sanitized_query(table_filter)

    def admin_user_management_endpoint(self):
        """Admin user management - COMPLEX CALL CHAIN"""
        auth_token = request.headers.get('Authorization', '')

        if not self.auth_manager.validate_admin_token(auth_token):
            return jsonify({"error": "Admin access required"}), 403

        action = request.args.get('action', '')
        user_id = request.args.get('user_id', '')

        return self.user_service.admin_user_management(action, user_id)

# Initialize controller
api_controller = APIController()

# Register routes - including new vulnerable endpoints
app.add_url_rule('/api/users/search', 'search_users', api_controller.search_users_endpoint, methods=['GET'])
app.add_url_rule('/api/users/details', 'get_user_details', api_controller.get_user_details_endpoint, methods=['GET'])
app.add_url_rule('/api/products/search', 'search_products', api_controller.search_products_endpoint, methods=['GET'])
app.add_url_rule('/profile', 'public_profile', api_controller.public_profile_endpoint, methods=['GET'])
app.add_url_rule('/profile/safe', 'safe_profile', api_controller.safe_profile_endpoint, methods=['GET'])
app.add_url_rule('/admin/users/manage', 'admin_user_management', api_controller.admin_user_management_endpoint, methods=['POST'])
app.add_url_rule('/api/users/complex_search', 'complex_user_search', api_controller.complex_user_search_endpoint, methods=['GET'])
app.add_url_rule('/api/reports/advanced', 'advanced_report', api_controller.advanced_report_endpoint, methods=['GET'])

# New vulnerable routes that Semgrep can detect
app.add_url_rule('/public_search', 'public_search_critical', api_controller.public_search_critical, methods=['GET'])
app.add_url_rule('/execute', 'direct_command', api_controller.direct_command_execution, methods=['GET'])
app.add_url_rule('/upload', 'file_upload', api_controller.file_upload_and_execute, methods=['GET'])
app.add_url_rule('/template', 'template_injection', api_controller.template_injection_endpoint, methods=['GET'])
app.add_url_rule('/debug', 'database_debug', api_controller.database_debug_endpoint, methods=['GET'])
app.add_url_rule('/read', 'file_read', api_controller.file_read_endpoint, methods=['GET'])
app.add_url_rule('/log', 'log_injection', api_controller.log_injection_endpoint, methods=['GET'])
app.add_url_rule('/script', 'subprocess', api_controller.subprocess_endpoint, methods=['GET'])
app.add_url_rule('/internal', 'internal_file', api_controller.internal_file_read, methods=['GET'])
app.add_url_rule('/custom_sql', 'custom_sql', api_controller.custom_sql_endpoint, methods=['GET'])
