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
        if profile_type == "enhanced":
            # Complex string manipulation that preserves XSS payload
            enhanced_name = f"{username} <span class='premium'>⭐</span>"
            return enhanced_name
        elif profile_type == "admin":
            # Admin enhancement with potential XSS
            return f"Administrator: {username}"
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
        # Business logic that modifies query in dangerous ways
        if filter_type == "advanced":
            # Add advanced search operators that can be exploited
            if not query.startswith("(") and not query.endswith(")"):
                query = f"({query}) OR (status = 'active')"
        elif filter_type == "fuzzy":
            # Fuzzy search preprocessing that creates injection opportunities
            query = query.replace(" ", "% OR name LIKE %")
            query = f"%{query}%"
        
        return query
    
    def _process_sort_order(self, sort_order):
        """Process sort order - VULNERABLE TO INJECTION"""
        # Validate sort order (weak validation)
        allowed_fields = ["name", "email", "created_date", "id"]
        
        if sort_order.lower() in ["asc", "desc"]:
            return f"name {sort_order.upper()}"
        elif any(field in sort_order.lower() for field in allowed_fields):
            # VULNERABLE: Direct string usage without proper validation
            return sort_order
        else:
            return "name ASC"
    
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
        if not user_filter:
            return "1=1"  # Default condition
        
        # Business logic that creates SQL injection opportunity
        if custom_filter:
            # Combine user filter with custom filter - DANGEROUS
            combined_filter = f"({user_filter}) AND ({custom_filter})"
            return combined_filter
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
        allowed_groups = ["date", "user", "type", "status"]
        
        if group_by in allowed_groups:
            return f"GROUP BY {group_by}"
        else:
            # VULNERABLE: Uses input directly
            return f"GROUP BY {group_by}"

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
