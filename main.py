#!/usr/bin/env python3
"""
Main Application Entry Point for Testing Complex Attack Paths
This serves as the primary entry point that demonstrates complex call chains
leading to various vulnerability sinks while also containing false positive patterns.
"""

import sys
import os
from typing import Optional, Dict, Any
from flask import Flask, request, jsonify

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from routes.vulnerability_routes import VulnerabilityRoutes
from routes.invoice_routes import InvoiceRoutes
from services.extended_services import CentralizedLogger, UserProfileService, OrderManagementService
from utils.logger import CentralizedLogger as UtilsLogger

app = Flask(__name__)

class MainApplication:
    """
    Main application class that orchestrates complex attack paths
    Contains both vulnerable and false positive patterns for comprehensive testing
    """
    
    def __init__(self):
        self.vuln_routes = VulnerabilityRoutes()
        self.invoice_routes = InvoiceRoutes()
        self.logger = CentralizedLogger()
        self.utils_logger = UtilsLogger()
        
        # Initialize services for complex call chains
        self.profile_service = UserProfileService()
        self.order_service = OrderManagementService()
        
    # ==================== VULNERABLE ENTRY POINTS ====================
    
    def process_user_registration(self, username: str, email: str, profile_data: Dict[str, Any]) -> str:
        """
        VULNERABLE: Complex call chain leading to template injection
        Entry Point → Business Logic → Service Layer → Vulnerable Sink
        """
        # Complex multi-layer processing
        processed_profile = self._validate_and_process_profile(username, email, profile_data)
        
        # Call service layer which leads to vulnerable sink
        result = self.profile_service.update_profile(
            processed_profile['username'], 
            processed_profile['email']
        )
        
        # VULNERABLE SINK: Template injection in response
        welcome_template = f"<h1>Welcome {username}!</h1><p>Registration complete: {result}</p>"
        from flask import render_template_string
        return render_template_string(welcome_template)
        
    def process_bulk_order_creation(self, order_list: list, admin_token: str) -> Dict[str, Any]:
        """
        VULNERABLE: Command injection through administrative bulk operations
        Entry Point → Validation → Service Layer → Command Execution Sink
        """
        # Administrative validation
        if not self._validate_admin_token(admin_token):
            return {"error": "Invalid admin token"}
            
        results = []
        for order_data in order_list:
            # Each order goes through the vulnerable service layer
            order_result = self.order_service.create_order(
                order_data.get('product_id', ''),
                order_data.get('user_id', ''),
                order_data.get('quantity', 1)
            )
            results.append(order_result)
        
        # VULNERABLE SINK: File write vulnerability in batch processing
        batch_summary = f"Processed {len(results)} orders for admin {admin_token}"
        log_file = f"/tmp/admin_operations/{admin_token}_batch.log"
        with open(log_file, 'w') as f:
            f.write(batch_summary)
            
        return {"status": "bulk_complete", "processed": len(results)}
    
    # ==================== FALSE POSITIVE PATTERNS ====================
    
    def secure_user_profile_display(self, user_id: str) -> str:
        """
        PROTECTED: Properly sanitized user profile display
        This should be classified as false_positive_sanitized
        """
        # Proper input validation
        if not self._is_valid_user_id(user_id):
            return "Invalid user ID"
            
        # Get user data through secure path
        user_data = self._get_user_data_securely(user_id)
        
        # PROTECTED: Proper HTML escaping prevents XSS
        import html
        safe_username = html.escape(user_data.get('username', 'Unknown'))
        safe_email = html.escape(user_data.get('email', 'No email'))
        
        # Template is safe due to proper escaping
        template = f"<div>User: {safe_username}</div><div>Email: {safe_email}</div>"
        from flask import render_template_string
        return render_template_string(template)
    
    def dead_code_vulnerability(self, malicious_input: str) -> str:
        """
        DEAD CODE: This function contains vulnerabilities but is never called
        Should be classified as false_positive_dead_code
        """
        # This condition is never true, making this code unreachable
        if hasattr(malicious_input, 'impossible_attribute') and malicious_input.impossible_attribute:
            # DEAD CODE: Template injection vulnerability in unreachable code
            dangerous_template = f"<script>alert('{malicious_input}')</script>"
            from flask import render_template_string
            return render_template_string(dangerous_template)
            
        return "safe_response"
    
    def protected_administrative_function(self, admin_command: str, auth_header: str) -> Dict[str, Any]:
        """
        PROTECTED: Administrative function with proper authorization
        Should be classified as false_positive_protected
        """
        # Strong authentication check
        if not self._verify_admin_authentication(auth_header):
            return {"error": "Unauthorized", "code": 401}
            
        # Additional authorization check
        if not self._check_admin_permissions(auth_header, 'system_commands'):
            return {"error": "Insufficient permissions", "code": 403}
        
        # Input sanitization for command execution
        sanitized_command = self._sanitize_admin_command(admin_command)
        
        # PROTECTED: Even though subprocess is used, it's properly protected
        import subprocess
        result = subprocess.run(['echo', sanitized_command], capture_output=True, text=True)
        
        return {"status": "command_executed", "output": result.stdout}
    
    # ==================== HELPER METHODS ====================
    
    def _validate_and_process_profile(self, username: str, email: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Business logic for profile processing - part of vulnerable call chain"""
        # Basic validation (insufficient)
        if len(username) < 3:
            raise ValueError("Username too short")
            
        return {
            'username': username,
            'email': email,
            'profile_data': profile_data,
            'processed_at': 'now()'
        }
    
    def _validate_admin_token(self, token: str) -> bool:
        """Weak validation - allows attack path to continue"""
        return len(token) > 10  # Insufficient validation
    
    def _is_valid_user_id(self, user_id: str) -> bool:
        """Proper validation for protected functions"""
        return user_id.isalnum() and 1 <= len(user_id) <= 50
        
    def _get_user_data_securely(self, user_id: str) -> Dict[str, str]:
        """Secure data retrieval with proper validation"""
        # Simulate secure database access
        return {
            'username': f'user_{user_id}',
            'email': f'user{user_id}@example.com'
        }
    
    def _verify_admin_authentication(self, auth_header: str) -> bool:
        """Strong authentication verification"""
        # Simulate proper JWT/token validation
        return auth_header.startswith('Bearer ') and len(auth_header) > 100
        
    def _check_admin_permissions(self, auth_header: str, permission: str) -> bool:
        """Proper permission checking"""
        # Simulate role-based access control
        return 'admin' in auth_header and permission in ['system_commands', 'user_management']
        
    def _sanitize_admin_command(self, command: str) -> str:
        """Proper input sanitization"""
        # Remove dangerous characters
        dangerous_chars = ['&', '|', ';', '$', '`', '>', '<', '(', ')']
        sanitized = command
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        return sanitized[:50]  # Limit length

# ==================== FLASK ROUTES ====================

main_app = MainApplication()

@app.route('/api/register', methods=['POST'])
def register_user():
    """VULNERABLE: User registration with complex attack path"""
    data = request.get_json()
    return main_app.process_user_registration(
        data.get('username', ''),
        data.get('email', ''),
        data.get('profile_data', {})
    )

@app.route('/api/admin/bulk-orders', methods=['POST'])
def bulk_create_orders():
    """VULNERABLE: Administrative bulk order processing"""
    data = request.get_json()
    admin_token = request.headers.get('Admin-Token', '')
    return jsonify(main_app.process_bulk_order_creation(
        data.get('orders', []),
        admin_token
    ))

@app.route('/api/profile/<user_id>', methods=['GET'])
def get_user_profile(user_id):
    """PROTECTED: Secure user profile display"""
    return main_app.secure_user_profile_display(user_id)

@app.route('/api/admin/execute', methods=['POST'])
def admin_execute():
    """PROTECTED: Administrative command execution with proper controls"""
    data = request.get_json()
    auth_header = request.headers.get('Authorization', '')
    return jsonify(main_app.protected_administrative_function(
        data.get('command', ''),
        auth_header
    ))

# Route to existing vulnerability modules
@app.route('/vuln/profile', methods=['POST'])
def vuln_profile_update():
    """Delegate to vulnerability routes module"""
    return main_app.vuln_routes.profile_update_endpoint()

@app.route('/vuln/order', methods=['POST'])
def vuln_order_create():
    """Delegate to vulnerability routes module"""
    return main_app.vuln_routes.order_create_endpoint()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
