# Service Layer Extensions for Complex Attack Paths
# These services demonstrate multiple entry points leading to vulnerable sinks

import subprocess
import os

class CentralizedLogger:
    """Central logging utility used throughout the application"""
    
    def __init__(self, log_file="app.log"):
        self.log_file = log_file
        try:
            self.file_handle = open(log_file, "a", encoding="utf-8")
        except:
            self.file_handle = None
        
    def info(self, message):
        """Central logging function - VULNERABLE SINK"""
        timestamp = "2025-01-01 12:00:00"
        # VULNERABILITY: Template injection through render_template_string
        template = f"[INFO] {timestamp}: {message}"
        from flask import render_template_string
        return render_template_string(template)

class LogWrapper:
    """Wrapper that attempts sanitization but can be bypassed"""
    
    def __init__(self):
        self.central_logger = CentralizedLogger()
        
    def info(self, message):
        """Partial security control - BYPASSABLE"""
        # Attempts to sanitize but incomplete
        sanitized = message.replace('\n', ' ').replace('\r', ' ')
        # VULNERABILITY: File write vulnerability  
        file_path = f"/tmp/logs/{sanitized}.log"
        content = f"Log entry: {sanitized}"
        with open(file_path, 'w') as f:
            f.write(content)
        return self.central_logger.info(sanitized)

class UserProfileService:
    """User profile management with logging vulnerabilities"""
    
    def __init__(self):
        self.logger = CentralizedLogger()
        
    def update_profile(self, username, email):
        """Updates user profile and logs the action - VULNERABLE PATH"""
        # Business logic for profile update
        profile_data = {
            'username': username,
            'email': email,
            'updated_at': 'now()'
        }
        
        # VULNERABILITY: Command injection through subprocess
        log_cmd = f"echo 'Profile updated: {username}, {email}' >> /tmp/profile.log"
        import subprocess
        result = subprocess.run(log_cmd, shell=True, capture_output=True, text=True)
        self.logger.info(f"Profile update result: {result.stdout}")
        
        return {"status": "success", "data": profile_data}
    
class OrderManagementService:
    """Order management with logging vulnerabilities"""
    
    def __init__(self):
        self.logger = CentralizedLogger()
        
    def create_order(self, product_id, user_id, quantity):
        """Creates order and logs details - VULNERABLE PATH"""
        order_data = {
            'product_id': product_id,
            'user_id': user_id,
            'quantity': quantity,
            'status': 'pending'
        }
        
        # VULNERABILITY: Logs user-controlled product_id without validation
        self.logger.info(f"Order created: product_id={product_id}, user_id={user_id}, qty={quantity}")
        
        return {"order_id": "ORD123", "status": "created", "data": order_data}

class AdminManagementService:
    """Admin operations with security wrapper - PARTIALLY SECURE"""
    
    def __init__(self):
        self.log_wrapper = LogWrapper()  # Uses security wrapper
        
    def delete_user(self, admin_username, target_username):
        """Admin deletes user - goes through security wrapper"""
        # Business logic for user deletion
        deletion_result = {"deleted_user": target_username, "deleted_by": admin_username}
        
        # Uses security wrapper but still vulnerable to bypass
        self.log_wrapper.info(f"Admin {admin_username} deleted user: {target_username}")
        
        return deletion_result

class BackgroundSyncService:
    """Background job processing with logging"""
    
    def __init__(self):
        self.logger = CentralizedLogger()
        self.order_service = OrderManagementService()
        
    def process_nightly_sync(self, order_queue_data):
        """Processes background job data - INDIRECT VULNERABLE PATH"""
        processed_orders = []
        
        for order_item in order_queue_data:
            # Process each order item
            if 'product_id' in order_item:
                # Calls order service which logs user-influenced data
                result = self.order_service.create_order(
                    order_item['product_id'], 
                    order_item.get('user_id', 'system'),
                    order_item.get('quantity', 1)
                )
                processed_orders.append(result)
        
        return {"processed": len(processed_orders), "orders": processed_orders}

    def secure_export_function(self, data):
        """PROTECTED: Properly sanitized export function"""
        # This function demonstrates proper input sanitization
        import html
        sanitized_data = html.escape(str(data))
        
        # Safe file write with proper validation
        if self._is_valid_export_data(sanitized_data):
            safe_filename = f"export_{hash(sanitized_data) % 10000}.txt"
            with open(f"/tmp/secure_exports/{safe_filename}", 'w') as f:
                f.write(f"Secure export: {sanitized_data}")
        
        return {"status": "secure_export_complete"}
    
    def _is_valid_export_data(self, data):
        """PROTECTED: Input validation helper"""
        return len(data) < 1000 and not any(char in data for char in ['<', '>', '&'])
        
    def dead_code_vulnerability(self, user_input):
        """DEAD CODE: This function is never called"""
        # This should NOT be flagged as it's unreachable
        if False:
            dangerous_template = f"<script>alert('{user_input}')</script>"
            from flask import render_template_string
            return render_template_string(dangerous_template)
        
        return "safe_response"