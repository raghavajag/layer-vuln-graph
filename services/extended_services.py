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


# ==================== COMMAND INJECTION VULNERABILITIES ====================

class SystemCommandService:
    """Service for system operations with command injection vulnerabilities"""
    
    def __init__(self):
        self.logger = CentralizedLogger()
    
    def ping_host(self, host):
        """CRITICAL: Command injection - no protections"""
        # Direct command execution with user input
        result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
        return result.decode()
    
    def execute_diagnostic(self, command):
        """CRITICAL: Direct command injection - immediately exploitable"""
        # No validation or sanitization
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return {
            "command": command,
            "output": result.stdout,
            "error": result.stderr,
            "return_code": result.returncode
        }
    
    def debug_network_command(self, cmd):
        """GOOD TO FIX: Command injection with weak validation"""
        # Weak attempt at validation
        if 'rm' not in cmd and 'del' not in cmd:
            result = subprocess.run(f"echo {cmd}", shell=True, capture_output=True)
            return result.stdout
        return "Command blocked"
    
    def run_batch_script(self, script_name, params):
        """CRITICAL: Command injection via script parameters"""
        # User-controlled parameters passed to command
        command = f"./scripts/{script_name}.sh {params}"
        result = os.system(command)
        return {"script": script_name, "exit_code": result}
    
    def admin_execute_command(self, command):
        """PROTECTED: Command execution but protected by decorator (see routes)"""
        # This function is protected by @staff_member_required decorator
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr}


# ==================== FILE OPERATION VULNERABILITIES ====================

class FileOperationsService:
    """Service for file operations with path traversal vulnerabilities"""
    
    def __init__(self):
        self.logger = CentralizedLogger()
        self.base_upload_path = "/uploads/"
    
    def read_user_file(self, filename):
        """GOOD TO FIX: Path traversal with weak validation"""
        # Attempts to prevent directory traversal but still vulnerable
        if '../' in filename or '/' in filename:
            return None
        
        # Still vulnerable to other traversal techniques
        try:
            with open(f"user_files/{filename}", 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None
    
    def upload_and_save_file(self, filename, content):
        """CRITICAL: Path traversal + potential RCE vulnerability"""
        # No path validation
        file_path = f"{self.base_upload_path}{filename}"
        
        with open(file_path, 'w') as f:
            f.write(content)
        
        return f"File saved to {file_path}"
    
    def read_internal_file(self, filepath):
        """GOOD TO FIX: Path traversal - lower impact (internal network)"""
        # Internal file access with minimal validation
        file_path = f"/internal_docs/{filepath}"
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            return {"content": content}
        except Exception as e:
            return {"error": str(e)}
    
    def get_file_by_path(self, filepath):
        """CRITICAL: Direct path traversal vulnerability"""
        # No validation at all
        with open(filepath, 'r') as f:
            return f.read()
    
    def safe_file_read(self, filename):
        """PROTECTED: Properly validated file access"""
        # Proper validation
        if not filename or '..' in filename or filename.startswith('/'):
            return {"error": "Invalid filename"}, 400
        
        safe_filename = os.path.basename(filename)
        allowed_extensions = ['.txt', '.pdf', '.jpg']
        
        if not any(safe_filename.endswith(ext) for ext in allowed_extensions):
            return {"error": "File type not allowed"}, 400
        
        file_path = os.path.join('/safe/uploads/', safe_filename)
        
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return {"error": "File not found"}, 404


# ==================== AUTHENTICATION AND CRYPTO VULNERABILITIES ====================

class AuthenticationService:
    """Service handling authentication with weak cryptography"""
    
    def __init__(self):
        self.logger = CentralizedLogger()
    
    def hash_password(self, password):
        """GOOD TO FIX: Weak password hashing"""
        import base64
        # Using base64 instead of proper password hashing
        return base64.b64encode(password.encode()).decode()
    
    def verify_password(self, password, stored_hash):
        """GOOD TO FIX: Weak password verification"""
        import base64
        hashed = base64.b64encode(password.encode()).decode()
        return hashed == stored_hash
    
    def validate_email(self, email):
        """GOOD TO FIX: Weak regex for input validation"""
        import re
        # Overly simplistic email validation
        pattern = r'.+@.+\..+'
        return re.match(pattern, email) is not None
    
    def generate_session_token(self, user_id):
        """GOOD TO FIX: Predictable token generation"""
        import hashlib
        # Weak token generation using predictable values
        token = hashlib.md5(f"{user_id}{os.getpid()}".encode()).hexdigest()
        return token
    
    def store_credentials(self, username, password):
        """CRITICAL: Hardcoded credentials"""
        # Hardcoded admin credentials
        admin_user = "admin"
        admin_pass = "supersecretpassword123"
        
        if username == admin_user:
            return {"error": "Username reserved"}
        
        return {"success": True}


# ==================== DEAD CODE WITH VULNERABILITIES ====================

def legacy_load_user_preferences(data):
    """DEAD CODE: This function is not called anywhere in the codebase"""
    import pickle
    import base64
    # Unsafe deserialization vulnerability
    return pickle.loads(base64.b64decode(data))

def deprecated_get_file(filepath):
    """DEAD CODE: This function is not called anywhere"""
    # Direct path traversal vulnerability
    with open(filepath, 'r') as f:
        return f.read()

def unused_command_executor(command):
    """DEAD CODE: This function is not referenced anywhere"""
    # Direct command injection
    return os.system(command)

def legacy_db_connect():
    """DEAD CODE: This function is unused"""
    import sqlite3
    # Hardcoded credentials in dead code
    username = "admin"
    password = "supersecretpassword123"
    conn = sqlite3.connect('old_database.db')
    return conn

def another_dead_function():
    """DEAD CODE: Another unused function with command injection"""
    from flask import request
    cmd = request.args.get('cmd')
    result = subprocess.run(f"echo {cmd}", shell=True, capture_output=True)
    return result.stdout