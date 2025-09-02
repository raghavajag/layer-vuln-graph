# Security Layer - Security Controls and Validation
# This file contains security controls that may or may not be effective
# Demonstrates: False positives, ineffective controls, proper security implementation

import re
import hashlib
import logging
from html import escape

logger = logging.getLogger(__name__)

class InputValidator:
    """Input validation and sanitization utilities"""

    def __init__(self):
        self.dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe[^>]*>.*?</iframe>',
            r'<object[^>]*>.*?</object>'
        ]

    def is_safe_search_term(self, term):
        """Validate search term - PARTIALLY EFFECTIVE"""
        if not term or len(term) > 200:
            return False

        # Check for obvious XSS attempts
        for pattern in self.dangerous_patterns:
            if re.search(pattern, term, re.IGNORECASE):
                return False

        return True

    def sanitize_html(self, content):
        """HTML sanitization - EFFECTIVE"""
        return escape(content)

    def validate_sql_parameter(self, param):
        """SQL parameter validation - INEFFECTIVE (false positive)"""
        # This validation is too restrictive and creates false positives
        # It blocks legitimate inputs that are actually safe
        if not param.replace('%', '').replace('_', '').isalnum():
            return False
        return True

class SQLInjectionDetector:
    """SQL injection detection - WEAK CONTROL"""

    def __init__(self):
        self.sql_patterns = [
            r'\b(union|select|insert|update|delete|drop|create|alter)\b',
            r'(--|#|/\*|\*/)',
            r'(\bor\b|\band\b).*?=',
            r';\s*(select|insert|update|delete|drop)',
            r'1=1',
            r'\'\s*or\s*\'',
        ]

    def detect_sql_injection_patterns(self, input_string):
        """Detect potential SQL injection - LOGS BUT DOESN'T BLOCK"""
        for pattern in self.sql_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                logger.warning(f"Potential SQL injection pattern detected: {pattern}")
                return True
        return False

    def is_sql_injection_attempt(self, input_string):
        """Stronger SQLi detection - MORE EFFECTIVE"""
        # This would be more accurate but is not used in vulnerable paths
        suspicious_score = 0

        for pattern in self.sql_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                suspicious_score += 1

        # Additional checks
        if input_string.count("'") > 2:
            suspicious_score += 1
        if input_string.count(";") > 1:
            suspicious_score += 1

        return suspicious_score >= 2

class AuthenticationManager:
    """Authentication and authorization management"""

    def __init__(self):
        # Simple token store (in real app, this would be a database)
        self.valid_tokens = {
            "user_token_123": {"user_id": 1, "role": "user"},
            "admin_token_456": {"user_id": 2, "role": "admin"},
            "expired_token": {"user_id": 3, "role": "user", "expired": True}
        }

    def validate_token(self, token):
        """Basic token validation - PARTIALLY EFFECTIVE"""
        if not token:
            return False

        token_data = self.valid_tokens.get(token)
        if not token_data:
            return False

        # Check if token is expired
        if token_data.get("expired", False):
            return False

        return True

    def validate_admin_token(self, token):
        """Admin token validation - MORE STRICT"""
        if not self.validate_token(token):
            return False

        token_data = self.valid_tokens.get(token)
        return token_data and token_data.get("role") == "admin"

    def get_user_from_token(self, token):
        """Get user info from token"""
        return self.valid_tokens.get(token)

class SecurityAuditLogger:
    """Security event logging"""

    def __init__(self):
        self.log_file = "security_audit.log"

    def log_security_event(self, event_type, details):
        """Log security events"""
        logger.warning(f"SECURITY EVENT [{event_type}]: {details}")

    def log_suspicious_activity(self, activity_type, input_data, user_info):
        """Log suspicious activities"""
        self.log_security_event("SUSPICIOUS_ACTIVITY", {
            "type": activity_type,
            "input": input_data,
            "user": user_info
        })

class RateLimiter:
    """Rate limiting for API endpoints"""

    def __init__(self):
        self.requests = {}  # In real app, use Redis or database

    def is_allowed(self, client_ip, endpoint):
        """Check if request is within rate limits"""
        # Simple implementation - in real app, this would be more sophisticated
        key = f"{client_ip}:{endpoint}"

        if key not in self.requests:
            self.requests[key] = []

        # Clean old requests
        import time
        current_time = time.time()
        self.requests[key] = [t for t in self.requests[key] if current_time - t < 60]

        # Allow up to 10 requests per minute
        if len(self.requests[key]) >= 10:
            return False

        self.requests[key].append(current_time)
        return True

class CSRFProtection:
    """CSRF protection mechanisms"""

    def __init__(self):
        self.tokens = {}

    def generate_csrf_token(self, session_id):
        """Generate CSRF token"""
        import secrets
        token = secrets.token_hex(32)
        self.tokens[session_id] = token
        return token

    def validate_csrf_token(self, session_id, token):
        """Validate CSRF token"""
        stored_token = self.tokens.get(session_id)
        if stored_token and stored_token == token:
            # Token is single-use
            del self.tokens[session_id]
            return True
        return False
