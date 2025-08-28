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
    Validate comment content for security - Security Layer ENTRY POINT
    Calls: preprocess_comment_input → scan_for_xss_patterns → apply_content_filters → finalize_comment_validation
    Expected vulnerability: Insufficient XSS protection through complex processing chain
    """
    logger.info(f"Validating comment content for user {user_id}")
    
    # Step 1: Preprocess input (Security)
    preprocessed_data = preprocess_comment_input(comment_text)
    
    # Step 2: Scan for XSS patterns (Security)
    scanned_data = scan_for_xss_patterns(preprocessed_data)
    
    # Step 3: Apply content filters (Security)
    filtered_data = apply_content_filters(scanned_data)
    
    # Step 4: Finalize validation (Security)
    final_validation = finalize_comment_validation(filtered_data)
    
    return final_validation

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

def preprocess_comment_input(comment_text: str) -> Dict[str, Any]:
    """
    Preprocess comment input - Security Layer preprocessing
    First level of comment security processing
    """
    logger.info("Preprocessing comment input")
    
    # Initial cleanup
    cleaned_text = comment_text.strip()
    
    # Extract metadata
    comment_metadata = {
        'original_length': len(comment_text),
        'cleaned_length': len(cleaned_text),
        'contains_html': bool(re.search(r'<[^>]+>', cleaned_text)),
        'contains_urls': bool(re.search(r'https?://', cleaned_text)),
        'mention_count': len(re.findall(r'@\w+', cleaned_text))
    }
    
    return {
        'processed_text': cleaned_text,
        'metadata': comment_metadata
    }

def scan_for_xss_patterns(comment_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Scan for XSS patterns - Security Layer detection
    Second level of comment security processing
    """
    logger.info("Scanning for XSS patterns")
    
    processed_text = comment_data['processed_text']
    metadata = comment_data['metadata']
    
    # XSS pattern detection (incomplete)
    xss_patterns = [
        r'<script[^>]*>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>'
    ]
    
    detected_patterns = []
    for pattern in xss_patterns:
        if re.search(pattern, processed_text, re.IGNORECASE):
            detected_patterns.append(pattern)
    
    scan_result = {
        'xss_patterns_found': detected_patterns,
        'risk_level': 'high' if detected_patterns else 'low',
        'scan_passed': len(detected_patterns) == 0
    }
    
    return {
        'processed_text': processed_text,
        'metadata': metadata,
        'xss_scan': scan_result
    }

def apply_content_filters(comment_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply content filters - Security Layer filtering
    Third level of comment security processing
    """
    logger.info("Applying content filters")
    
    processed_text = comment_data['processed_text']
    xss_scan = comment_data['xss_scan']
    
    # Apply filters based on scan results
    if xss_scan['risk_level'] == 'high':
        # Weak filtering - just remove obvious patterns
        for pattern in xss_scan['xss_patterns_found']:
            processed_text = re.sub(pattern, '[FILTERED]', processed_text, flags=re.IGNORECASE)
    
    # Apply additional content policies
    filtered_text = apply_content_policies(processed_text)
    
    filter_result = {
        'filters_applied': xss_scan['risk_level'] == 'high',
        'content_modified': filtered_text != comment_data['processed_text'],
        'final_risk_assessment': assess_final_content_risk(filtered_text)
    }
    
    return {
        'processed_text': filtered_text,
        'metadata': comment_data['metadata'],
        'xss_scan': xss_scan,
        'filter_result': filter_result
    }

def apply_content_policies(text: str) -> str:
    """
    Apply content policies - Security Layer policy enforcement
    Security utility for content filtering
    """
    # Basic content policy filters
    policy_filters = [
        (r'\b(spam|scam|phishing)\b', '[POLICY_VIOLATION]'),
        (r'[A-Z]{10,}', lambda m: m.group().lower()),  # Reduce shouting
    ]
    
    filtered_text = text
    for pattern, replacement in policy_filters:
        if callable(replacement):
            filtered_text = re.sub(pattern, replacement, filtered_text)
        else:
            filtered_text = re.sub(pattern, replacement, filtered_text, flags=re.IGNORECASE)
    
    return filtered_text

def assess_final_content_risk(text: str) -> Dict[str, Any]:
    """
    Assess final content risk - Security Layer risk assessment
    Final security assessment before storage
    """
    risk_factors = {
        'length_risk': 'high' if len(text) > 1000 else 'low',
        'special_char_risk': 'medium' if re.search(r'[<>"\']', text) else 'low',
        'url_risk': 'medium' if re.search(r'https?://', text) else 'low',
        'mention_risk': 'low'  # Mentions are generally safe
    }
    
    # Calculate overall risk
    high_risks = sum(1 for risk in risk_factors.values() if risk == 'high')
    medium_risks = sum(1 for risk in risk_factors.values() if risk == 'medium')
    
    if high_risks > 0:
        overall_risk = 'high'
    elif medium_risks > 1:
        overall_risk = 'medium'
    else:
        overall_risk = 'low'
    
    return {
        'risk_factors': risk_factors,
        'overall_risk': overall_risk,
        'recommended_action': 'store' if overall_risk != 'high' else 'reject'
    }

def finalize_comment_validation(comment_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Finalize comment validation - Security Layer final validation
    Last security check before approving content
    """
    logger.info("Finalizing comment validation")
    
    final_risk = comment_data['filter_result']['final_risk_assessment']
    
    # Make final decision
    is_approved = final_risk['recommended_action'] == 'store'
    
    validation_result = {
        'is_valid': is_approved,
        'reason': 'Content approved' if is_approved else f"Content rejected due to {final_risk['overall_risk']} risk",
        'processed_content': comment_data['processed_text'],
        'security_metadata': {
            'xss_scan': comment_data['xss_scan'],
            'filter_result': comment_data['filter_result'],
            'final_assessment': final_risk
        }
    }
    
    return validation_result