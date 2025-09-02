# Business Layer - Core Business Logic
# This file contains business logic that processes data from API layer
# Demonstrates: Data transformation, business rules, multiple call paths

from .security_layer import InputValidator, SQLInjectionDetector
from .data_layer import DatabaseManager, UserRepository, ProductRepository
from .security_layer import AuthenticationManager
import logging

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
        # Business logic processing
        if not user_id.isdigit():
            return {"error": "Invalid user ID format"}

        # Format user ID for database (vulnerable string formatting)
        formatted_id = self._format_user_id_for_db(user_id)

        # Call data layer
        return self.user_repo.get_user_by_id(formatted_id)

    def _preprocess_search_query(self, query):
        """Preprocess search query - adds complexity to call chain"""
        # Business logic transformations
        query = query.strip()
        query = query.lower()

        # Add wildcards (creates SQL injection opportunity)
        if not query.startswith('%'):
            query = f"%{query}%"

        return query

    def _format_user_id_for_db(self, user_id):
        """Format user ID for database - VULNERABLE"""
        # This creates a classic SQL injection vulnerability
        return f"WHERE id = {user_id}"

    def get_user_details(self, user_id, is_admin=False):
        """Get detailed user information"""
        if is_admin:
            # Admin path - different processing
            return self._get_admin_user_details(user_id)
        else:
            # Regular user path
            return self._get_regular_user_details(user_id)

    def _get_admin_user_details(self, user_id):
        """Admin user details - complex call chain"""
        # Multiple data calls for admin view
        user_data = self.user_repo.get_user_by_id(user_id)
        user_permissions = self.user_repo.get_user_permissions(user_id)
        user_activity = self.user_repo.get_user_activity(user_id)

        return {
            "user": user_data,
            "permissions": user_permissions,
            "activity": user_activity
        }

    def _get_regular_user_details(self, user_id):
        """Regular user details - simpler path"""
        return self.user_repo.get_user_by_id(user_id)

    def admin_user_management(self, action, user_id):
        """Admin user management - demonstrates privilege escalation potential"""
        logger.info(f"Admin action: {action} on user: {user_id}")

        if action == "delete":
            return self.user_repo.delete_user(user_id)
        elif action == "promote":
            return self.user_repo.promote_user_to_admin(user_id)
        elif action == "demote":
            return self.user_repo.demote_user_from_admin(user_id)
        else:
            return {"error": "Unknown action"}

class ProductService:
    """Product management business logic"""

    def __init__(self):
        self.validator = InputValidator()
        self.product_repo = ProductRepository()

    def search_products(self, search_term):
        """Product search with proper sanitization"""
        logger.info(f"Searching products with term: {search_term}")

        # Input is already sanitized by API layer
        return self.product_repo.search_products(search_term)

class SearchService:
    """General search service"""

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
