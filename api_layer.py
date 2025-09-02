# API Layer - Entry Points for Attack Vectors
# This file contains various API endpoints that serve as entry points for attacks
# Demonstrates: Input validation, route handling, parameter processing

from flask import Flask, request, jsonify
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
        """Public profile display - XSS VULNERABLE"""
        username = request.args.get('username', '')

        # Direct output without encoding - VULNERABLE
        return f"<h1>Welcome {username}</h1>"

    def safe_profile_endpoint(self):
        """Safe profile with encoding - SECURE"""
        username = request.args.get('username', '')

        # Proper HTML encoding prevents XSS
        from html import escape
        safe_username = escape(username)
        return f"<h1>Welcome {safe_username}</h1>"

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

# Register routes
app.add_url_rule('/api/users/search', 'search_users', api_controller.search_users_endpoint, methods=['GET'])
app.add_url_rule('/api/users/details', 'get_user_details', api_controller.get_user_details_endpoint, methods=['GET'])
app.add_url_rule('/api/products/search', 'search_products', api_controller.search_products_endpoint, methods=['GET'])
app.add_url_rule('/profile', 'public_profile', api_controller.public_profile_endpoint, methods=['GET'])
app.add_url_rule('/profile/safe', 'safe_profile', api_controller.safe_profile_endpoint, methods=['GET'])
app.add_url_rule('/admin/users/manage', 'admin_user_management', api_controller.admin_user_management_endpoint, methods=['POST'])
