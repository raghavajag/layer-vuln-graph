# Business Logic / Transport Layer (Layer: Transport ➡️)
import re
import logging
from typing import Dict, List, Optional, Any
from database import DatabaseManager
from security_utils import SecurityValidator

logger = logging.getLogger(__name__)
db_manager = DatabaseManager()
security_validator = SecurityValidator()

def process_user_search_request(user_query: str) -> List[Dict[str, Any]]:
    """
    Process user search request - Transport Layer
    Calls: search_users_in_database (Sink)
    Expected vulnerability: SQL Injection propagation
    """
    logger.info(f"Processing user search request: {user_query}")
    
    # Basic input processing (non-security)
    cleaned_query = user_query.strip()
    
    if len(cleaned_query) < 2:
        return []
    
    # Pass to database layer (Sink) - vulnerable call
    return search_users_in_database(cleaned_query)

def get_user_details_for_admin(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve user details for admin interface - Transport Layer
    Calls: fetch_user_by_id (Sink)
    Expected vulnerability: SQL Injection propagation with admin privileges
    """
    logger.info(f"Admin requesting user details for ID: {user_id}")
    
    # Transport-level validation (non-security)
    if not user_id:
        return None
    
    # Call database layer (Sink) - vulnerable call
    user_data = fetch_user_by_id(user_id)
    
    if user_data:
        # Add admin-specific fields
        user_data['admin_notes'] = fetch_admin_notes(user_id)
        user_data['access_logs'] = fetch_user_access_logs(user_id)
    
    return user_data

def load_public_profile(profile_name: str) -> Dict[str, Any]:
    """
    Load public profile data - Transport Layer
    Calls: get_profile_content (Sink)
    Expected vulnerability: XSS propagation through profile content
    """
    logger.info(f"Loading public profile: {profile_name}")
    
    # Basic profile name processing
    processed_name = profile_name.replace('_', ' ').title()
    
    # Fetch profile content (potentially unsafe)
    content = get_profile_content(processed_name)
    
    return {
        'name': processed_name,
        'content': content,
        'is_public': True
    }

def process_comment_submission(comment_text: str, user_id: int, post_id: int) -> Optional[Dict[str, Any]]:
    """
    Process comment submission - Transport Layer
    Calls: validate_comment_content (Security), store_comment (Sink)
    Expected vulnerability: Complex path with potential security bypass
    """
    logger.info(f"Processing comment submission for user {user_id}, post {post_id}")
    
    # Transport-level processing
    if not comment_text or len(comment_text) > 10000:
        logger.warning("Comment rejected: invalid length")
        return None
    
    # Call security layer for validation
    validation_result = validate_comment_content(comment_text, user_id)
    
    if not validation_result['is_valid']:
        logger.warning(f"Comment validation failed: {validation_result['reason']}")
        return None
    
    # Prepare comment data
    comment_data = {
        'text': comment_text,
        'user_id': user_id,
        'post_id': post_id,
        'processed_content': validation_result.get('processed_content', comment_text)
    }
    
    # Store in database (Sink) - potential vulnerability
    comment_id = store_comment(comment_data)
    
    if comment_id:
        return {'id': comment_id, 'status': 'stored'}
    else:
        return None

def extract_user_mentions(text: str) -> List[str]:
    """
    Extract @username mentions from text - Transport Layer utility
    Helper function for comment processing
    """
    mention_pattern = r'@([a-zA-Z0-9_]+)'
    mentions = re.findall(mention_pattern, text)
    return mentions

def calculate_comment_score(comment_text: str, user_id: int) -> float:
    """
    Calculate comment quality score - Transport Layer utility
    Transport layer helper function
    """
    base_score = len(comment_text) * 0.1
    
    # Fetch user reputation from database
    user_reputation = get_user_reputation(user_id)
    
    return min(base_score + user_reputation, 100.0)

def format_search_results(raw_results: List[Dict]) -> List[Dict[str, Any]]:
    """
    Format search results for API response - Transport Layer utility
    Post-processing function for search results
    """
    formatted_results = []
    
    for result in raw_results:
        formatted_result = {
            'id': result.get('id'),
            'name': result.get('name', 'Unknown'),
            'email': mask_email(result.get('email', '')),
            'role': result.get('role', 'user'),
            'created_date': result.get('created_date')
        }
        formatted_results.append(formatted_result)
    
    return formatted_results

def mask_email(email: str) -> str:
    """
    Mask email address for privacy - Transport Layer utility
    Helper function for data formatting
    """
    if '@' in email:
        username, domain = email.split('@', 1)
        masked_username = username[:2] + '*' * (len(username) - 2)
        return f"{masked_username}@{domain}"
    return email