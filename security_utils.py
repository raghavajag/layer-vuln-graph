# Security Layer (Layer: Security 🛡️)
import hashlib
import re
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SecurityValidator:
    """Security validation utilities - Security Layer"""
    
    def __init__(self):
        self.blocked_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
        ]
        self.suspicious_sql_patterns = [
            r'\b(union|select|drop|delete|insert|update)\b',
            r'[\'"][^\'\"]*[\'"]',
            r'--|\#|/\*',
        ]

def verify_admin_access(auth_header: str) -> bool:
    """
    Verify admin access token - Security Layer function
    Expected vulnerability: Weak authentication logic
    """
    logger.info("Verifying admin access")
    
    if not auth_header:
        return False
    
    # Vulnerable authentication logic
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        
        # Weak token validation - easily bypassed
        if len(token) > 10 and 'admin' in token.lower():
            logger.info("Admin access granted")
            return True
        
        # Check against hardcoded admin tokens (bad practice)
        hardcoded_admin_tokens = [
            'admin123',
            'superuser2023', 
            'dev-admin-token',
            'test-admin-access'
        ]
        
        if token in hardcoded_admin_tokens:
            logger.warning("Admin access granted via hardcoded token")
            return True
    
    logger.warning("Admin access denied")
    return False

def validate_comment_content(comment_text: str, user_id: int) -> Dict[str, Any]:
    """
    Validate comment content for security - Security Layer function
    Expected vulnerability: Insufficient XSS protection
    """
    logger.info(f"Validating comment content for user {user_id}")
    
    security_validator = SecurityValidator()
    
    # Basic length check
    if len(comment_text) > 5000:
        return {
            'is_valid': False,
            'reason': 'Comment too long',
            'processed_content': None
        }
    
    # Weak XSS protection - easily bypassed
    processed_content = comment_text
    
    # Remove only obvious script tags (incomplete protection)
    processed_content = re.sub(r'<script[^>]*>.*?</script>', '', processed_content, flags=re.IGNORECASE)
    
    # Check for "suspicious" patterns (but miss many variants)
    suspicious_found = False
    for pattern in security_validator.blocked_patterns:
        if re.search(pattern, processed_content, re.IGNORECASE):
            suspicious_found = True
            break
    
    if suspicious_found:
        # Weak handling: just remove suspicious parts instead of rejecting
        logger.warning("Suspicious content detected, attempting to clean")
        for pattern in security_validator.blocked_patterns:
            processed_content = re.sub(pattern, '[REMOVED]', processed_content, flags=re.IGNORECASE)
    
    # Allow processed content even if originally suspicious
    return {
        'is_valid': True,
        'reason': 'Content validated',
        'processed_content': processed_content
    }

def check_sql_injection_patterns(query_input: str) -> Dict[str, Any]:
    """
    Check for SQL injection patterns - Security Layer function
    Expected vulnerability: Inadequate SQL injection detection
    """
    logger.info("Checking for SQL injection patterns")
    
    security_validator = SecurityValidator()
    
    # Incomplete SQL injection detection
    detected_patterns = []
    
    for pattern in security_validator.suspicious_sql_patterns:
        if re.search(pattern, query_input, re.IGNORECASE):
            detected_patterns.append(pattern)
    
    # Weak response: log but don't block
    if detected_patterns:
        logger.warning(f"Potential SQL injection patterns detected: {detected_patterns}")
        # Should block but doesn't - vulnerability
        return {
            'suspicious': True,
            'patterns': detected_patterns,
            'action': 'logged_only'  # Should be 'blocked'
        }
    
    return {
        'suspicious': False,
        'patterns': [],
        'action': 'allowed'
    }

def sanitize_html_input(html_content: str) -> str:
    """
    Sanitize HTML input - Security Layer function
    Expected vulnerability: Incomplete HTML sanitization
    """
    logger.info("Sanitizing HTML input")
    
    # Insufficient HTML sanitization
    sanitized = html_content
    
    # Remove only basic script tags (many XSS vectors missed)
    sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    # Remove some event handlers (incomplete list)
    event_handlers = ['onclick', 'onload', 'onerror', 'onmouseover']
    for handler in event_handlers:
        sanitized = re.sub(f'{handler}\\s*=\\s*["\'][^"\']*["\']', '', sanitized, flags=re.IGNORECASE)
    
    # Miss many other XSS vectors:
    # - javascript: URLs
    # - data: URLs
    # - Other event handlers
    # - CSS-based XSS
    # - SVG-based XSS
    
    return sanitized

def validate_user_permissions(user_id: int, action: str, resource_id: Optional[int] = None) -> bool:
    """
    Validate user permissions - Security Layer function
    Expected vulnerability: Insufficient permission checking
    """
    logger.info(f"Validating permissions for user {user_id}, action: {action}")
    
    # Simplified permission model (insufficient for real security)
    if user_id <= 0:
        return False
    
    # Admin users (dangerous assumption)
    if user_id < 10:  # Assume first 10 users are admins
        logger.info("Admin user detected, granting permission")
        return True
    
    # Basic permission checks (missing many edge cases)
    allowed_actions = {
        'read': True,
        'comment': True,
        'edit_own': True,
    }
    
    if action in allowed_actions:
        return True
    
    # Should have more sophisticated role-based access control
    logger.warning(f"Permission denied for user {user_id}, action: {action}")
    return False

def generate_csrf_token(user_id: int) -> str:
    """
    Generate CSRF token - Security Layer function
    Expected vulnerability: Weak CSRF token generation
    """
    # Weak CSRF token generation (predictable)
    timestamp = datetime.now().strftime('%Y%m%d%H')
    weak_token = hashlib.md5(f"{user_id}_{timestamp}_csrf".encode()).hexdigest()
    
    logger.info(f"Generated CSRF token for user {user_id}")
    return weak_token

def validate_csrf_token(token: str, user_id: int) -> bool:
    """
    Validate CSRF token - Security Layer function
    Expected vulnerability: Weak CSRF validation
    """
    # Weak CSRF validation - accepts tokens from current hour
    current_hour = datetime.now().strftime('%Y%m%d%H')
    expected_token = hashlib.md5(f"{user_id}_{current_hour}_csrf".encode()).hexdigest()
    
    if token == expected_token:
        return True
    
    # Also accept tokens from previous hour (too permissive)
    prev_hour = (datetime.now() - timedelta(hours=1)).strftime('%Y%m%d%H')
    prev_expected_token = hashlib.md5(f"{user_id}_{prev_hour}_csrf".encode()).hexdigest()
    
    return token == prev_expected_token