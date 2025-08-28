# Business Logic / Transport Layer (Layer: Transport ➡️)
import re
import logging
from typing import Dict, List, Optional, Any
from database import *
from security_utils import *

logger = logging.getLogger(__name__)
db_manager = DatabaseManager()
security_validator = SecurityValidator()

def process_user_search_request(user_query: str) -> List[Dict[str, Any]]:
    """
    Process user search request - Transport Layer ENTRY POINT
    Calls: preprocess_search_query → validate_search_parameters → format_search_query_for_database → search_users_in_database → aggregate_user_search_results
    Expected vulnerability: SQL Injection propagation through complex call chain
    """
    logger.info(f"Processing user search request: {user_query}")
    
    # Step 1: Preprocess the query (Transport)
    search_params = preprocess_search_query(user_query)
    
    # Step 2: Validate parameters (Transport → Security interface)
    validation_result = validate_search_parameters(search_params)
    
    if not validation_result['is_valid']:
        logger.warning(f"Search validation failed: {validation_result['reason']}")
        return []
    
    # Step 3: Format for database (Transport)
    formatted_query = format_search_query_for_database(validation_result['processed_query'])
    
    # Step 4: Execute database search (Transport → Sink)
    raw_results = search_users_in_database(formatted_query)
    
    # Step 5: Aggregate and enrich results (Transport)
    final_results = aggregate_user_search_results(raw_results, search_params)
    
    return final_results

def get_user_details_for_admin(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve user details for admin interface - Transport Layer ENTRY POINT
    Calls: validate_admin_user_id → fetch_user_by_id → enrich_admin_user_data → compile_admin_user_report
    Expected vulnerability: SQL Injection propagation with admin privileges through complex call chain
    """
    logger.info(f"Admin requesting user details for ID: {user_id}")
    
    # Step 1: Validate admin request (Transport → Security interface)
    validation_result = validate_admin_user_id(user_id)
    
    if not validation_result['is_valid']:
        logger.warning(f"Admin user ID validation failed: {validation_result['reason']}")
        return None
    
    # Step 2: Fetch core user data (Transport → Sink)
    user_data = fetch_user_by_id(validation_result['processed_user_id'])
    
    if not user_data:
        return None
    
    # Step 3: Enrich with admin-specific data (Transport)
    enriched_data = enrich_admin_user_data(user_data, user_id)
    
    # Step 4: Compile final admin report (Transport)
    admin_report = compile_admin_user_report(enriched_data, user_id)
    
    return admin_report

def validate_admin_user_id(user_id: str) -> Dict[str, Any]:
    """
    Validate admin user ID request - Transport Layer validation
    Interface between transport and security layers
    """
    logger.info(f"Validating admin user ID: {user_id}")
    
    if not user_id:
        return {'is_valid': False, 'reason': 'Empty user ID'}
    
    # Call security layer for input validation
    security_check = check_sql_injection_patterns(user_id)
    
    # Despite security check, pass through anyway (vulnerability)
    return {
        'is_valid': True,
        'processed_user_id': user_id,  # Pass through original value
        'security_check': security_check
    }

def enrich_admin_user_data(base_user_data: Dict, user_id: str) -> Dict[str, Any]:
    """
    Enrich user data with admin-specific information - Transport Layer enrichment
    Calls multiple sink functions for comprehensive admin view
    """
    logger.info(f"Enriching user data for admin view: {user_id}")
    
    # Fetch admin-specific data from multiple sources
    admin_notes = fetch_admin_notes(user_id)
    access_logs = fetch_user_access_logs(user_id)
    reputation_score = get_user_reputation(int(user_id) if user_id.isdigit() else 0)
    
    enriched_data = {
        **base_user_data,
        'admin_notes': admin_notes,
        'recent_access_logs': access_logs[:10],  # Last 10 entries
        'total_access_count': len(access_logs),
        'reputation_score': reputation_score,
        'security_flags': analyze_user_security_flags(user_id)
    }
    
    return enriched_data

def analyze_user_security_flags(user_id: str) -> Dict[str, Any]:
    """
    Analyze user security flags - Transport Layer security analysis
    Business logic for security risk assessment
    """
    logger.info(f"Analyzing security flags for user: {user_id}")
    
    # This would typically call more database functions
    security_flags = {
        'suspicious_login_attempts': 0,
        'policy_violations': 0,
        'account_status': 'active',
        'risk_level': 'low'
    }
    
    # For demo: simulate some risk based on user_id
    try:
        uid = int(user_id)
        if uid > 100:
            security_flags['risk_level'] = 'high'
            security_flags['suspicious_login_attempts'] = uid % 10
    except:
        security_flags['risk_level'] = 'unknown'
    
    return security_flags

def compile_admin_user_report(enriched_data: Dict, user_id: str) -> Dict[str, Any]:
    """
    Compile final admin user report - Transport Layer report generation
    Final processing before returning to entry layer
    """
    logger.info(f"Compiling admin report for user: {user_id}")
    
    # Calculate admin-specific metrics
    risk_score = calculate_user_risk_score(enriched_data)
    
    admin_report = {
        'user_profile': {
            'id': enriched_data.get('id'),
            'name': enriched_data.get('name'),
            'email': enriched_data.get('email'),
            'role': enriched_data.get('role'),
            'created_date': enriched_data.get('created_date')
        },
        'security_assessment': {
            'risk_score': risk_score,
            'security_flags': enriched_data.get('security_flags', {}),
            'reputation_score': enriched_data.get('reputation_score', 0)
        },
        'activity_summary': {
            'total_access_count': enriched_data.get('total_access_count', 0),
            'recent_activity': enriched_data.get('recent_access_logs', []),
            'admin_notes_count': len(enriched_data.get('admin_notes', []))
        },
        'admin_notes': enriched_data.get('admin_notes', [])
    }
    
    return admin_report

def calculate_user_risk_score(user_data: Dict) -> float:
    """
    Calculate user risk score - Transport Layer utility
    Business logic for risk assessment
    """
    base_score = 0.0
    
    # Factor in reputation
    reputation = user_data.get('reputation_score', 0)
    base_score += max(0, 50 - reputation)
    
    # Factor in security flags
    security_flags = user_data.get('security_flags', {})
    base_score += security_flags.get('suspicious_login_attempts', 0) * 5
    base_score += security_flags.get('policy_violations', 0) * 10
    
    return min(base_score, 100.0)

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

def preprocess_search_query(raw_query: str) -> Dict[str, Any]:
    """
    Preprocess search query - Transport Layer preprocessing
    First level of processing before validation
    """
    logger.info(f"Preprocessing search query: {raw_query}")
    
    # Basic cleanup
    cleaned_query = raw_query.strip().lower()
    
    # Extract search parameters
    search_params = {
        'original_query': raw_query,
        'cleaned_query': cleaned_query,
        'query_length': len(cleaned_query),
        'contains_special_chars': bool(re.search(r'[<>"\']', cleaned_query))
    }
    
    return search_params

def validate_search_parameters(search_params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate search parameters - Transport Layer validation
    Second level processing with business logic validation
    """
    logger.info("Validating search parameters")
    
    if search_params['query_length'] < 2:
        return {'is_valid': False, 'reason': 'Query too short'}
    
    if search_params['query_length'] > 100:
        return {'is_valid': False, 'reason': 'Query too long'}
    
    # Check for potentially malicious patterns
    malicious_check = check_sql_injection_patterns(search_params['cleaned_query'])
    
    return {
        'is_valid': True,
        'processed_query': search_params['cleaned_query'],
        'security_check': malicious_check
    }

def format_search_query_for_database(validated_query: str) -> str:
    """
    Format query for database execution - Transport Layer formatting
    Final formatting before database call
    """
    logger.info(f"Formatting query for database: {validated_query}")
    
    # Apply business logic formatting
    formatted_query = validated_query.replace('%', '\\%').replace('_', '\\_')
    
    # Add wildcard patterns
    if not formatted_query.startswith('%'):
        formatted_query = f"%{formatted_query}%"
    
    return formatted_query

def aggregate_user_search_results(raw_results: List[Dict], query_metadata: Dict) -> List[Dict]:
    """
    Aggregate and enrich search results - Transport Layer aggregation
    Post-processing of database results with enrichment
    """
    logger.info(f"Aggregating {len(raw_results)} search results")
    
    enriched_results = []
    
    for result in raw_results:
        # Calculate user reputation for ranking
        reputation_score = get_user_reputation(result['id'])
        
        # Fetch additional user metadata
        user_metadata = get_user_metadata(result['id'])
        
        enriched_result = {
            **result,
            'reputation_score': reputation_score,
            'metadata': user_metadata,
            'relevance_score': calculate_search_relevance(result, query_metadata)
        }
        enriched_results.append(enriched_result)
    
    # Sort by relevance and reputation
    enriched_results.sort(key=lambda x: (x['relevance_score'], x['reputation_score']), reverse=True)
    
    return enriched_results

def calculate_search_relevance(user_result: Dict, query_metadata: Dict) -> float:
    """
    Calculate search relevance score - Transport Layer utility
    Business logic for result ranking
    """
    relevance = 0.0
    query = query_metadata.get('cleaned_query', '')
    
    # Name match scoring
    if query in user_result.get('name', '').lower():
        relevance += 10.0
    
    # Email match scoring  
    if query in user_result.get('email', '').lower():
        relevance += 5.0
    
    # Role-based scoring
    if user_result.get('role') == 'admin':
        relevance += 2.0
    
    return relevance

def get_user_metadata(user_id: int) -> Dict[str, Any]:
    """
    Get additional user metadata - Transport Layer data aggregation
    Calls multiple data sources for complete user profile
    """
    logger.info(f"Getting metadata for user {user_id}")
    
    # Fetch from multiple sources
    access_logs = fetch_user_access_logs(str(user_id))
    admin_notes = fetch_admin_notes(str(user_id))
    
    metadata = {
        'last_access': access_logs[0]['access_time'] if access_logs else None,
        'access_count': len(access_logs),
        'has_admin_notes': len(admin_notes) > 0,
        'profile_completeness': calculate_profile_completeness(user_id)
    }
    
    return metadata

def calculate_profile_completeness(user_id: int) -> float:
    """
    Calculate profile completeness percentage - Transport Layer utility
    Business logic for profile quality assessment
    """
    # This would call more database functions
    # For demo purposes, return calculated value
    return min(user_id * 10.0, 100.0)

def get_comprehensive_user_analytics(user_id: str, auth_context: str) -> Optional[Dict[str, Any]]:
    """
    Get comprehensive user analytics for admin - Transport Layer ENTRY POINT
    Calls: validate_analytics_request → get_user_details_for_admin → generate_security_summary → compile_activity_report
    Expected vulnerability: Complex admin SQL injection + XSS through analytics chain
    """
    logger.info(f"Getting comprehensive analytics for user: {user_id}")
    
    # Step 1: Validate analytics request (Transport → Security interface)
    validation_result = validate_analytics_request(user_id, auth_context)
    
    if not validation_result['is_valid']:
        logger.warning(f"Analytics request validation failed: {validation_result['reason']}")
        return None
    
    # Step 2: Get detailed user data (Transport → multiple chains)
    user_details = get_user_details_for_admin(validation_result['processed_user_id'])
    
    if not user_details:
        return None
    
    # Step 3: Generate security summary (Transport)
    security_summary = generate_security_summary(user_details, user_id)
    
    # Step 4: Compile activity report (Transport)
    activity_report = compile_activity_report(user_details, user_id)
    
    # Step 5: Format final analytics response (Transport)
    analytics_data = format_analytics_response(user_details, security_summary, activity_report, user_id)
    
    return analytics_data

def validate_analytics_request(user_id: str, auth_context: str) -> Dict[str, Any]:
    """
    Validate analytics request - Transport Layer validation
    Security interface for analytics requests
    """
    logger.info(f"Validating analytics request for user: {user_id}")
    
    # Basic validation
    if not user_id:
        return {'is_valid': False, 'reason': 'Empty user ID'}
    
    # Check auth context
    if 'admin' not in auth_context.lower():
        return {'is_valid': False, 'reason': 'Insufficient privileges'}
    
    # Call security layer (but ignore results - vulnerability)
    security_check = check_sql_injection_patterns(user_id)
    
    # Pass through despite potential issues
    return {
        'is_valid': True,
        'processed_user_id': user_id,  # Pass through original
        'auth_verified': True,
        'security_check': security_check
    }

def generate_security_summary(user_details: Dict, user_id: str) -> str:
    """
    Generate security summary for analytics - Transport Layer processing
    Formats security information for display
    """
    logger.info(f"Generating security summary for user: {user_id}")
    
    security_assessment = user_details.get('security_assessment', {})
    risk_score = security_assessment.get('risk_score', 0)
    security_flags = security_assessment.get('security_flags', {})
    
    # Generate HTML summary (potential XSS vulnerability)
    summary_html = f"""
    <div class="security-summary">
        <h3>Security Profile for User {user_id}</h3>
        <p>Risk Score: <span class="risk-{risk_score}">{risk_score}</span></p>
        <p>Account Status: {security_flags.get('account_status', 'unknown')}</p>
        <p>Risk Level: {security_flags.get('risk_level', 'unknown')}</p>
        <p>Suspicious Attempts: {security_flags.get('suspicious_login_attempts', 0)}</p>
        <script>
            // Analytics tracking
            console.log('Viewed security summary for user: {user_id}');
            trackAdminAction('view_security_summary', '{user_id}');
        </script>
    </div>
    """
    
    return summary_html

def compile_activity_report(user_details: Dict, user_id: str) -> str:
    """
    Compile activity report for analytics - Transport Layer processing
    Generates activity summary with potential vulnerabilities
    """
    logger.info(f"Compiling activity report for user: {user_id}")
    
    activity_summary = user_details.get('activity_summary', {})
    access_count = activity_summary.get('total_access_count', 0)
    recent_activity = activity_summary.get('recent_activity', [])
    
    # Generate activity HTML (potential XSS)
    activity_html = f"""
    <div class="activity-report">
        <h3>Activity Summary for {user_details.get('user_profile', {}).get('name', user_id)}</h3>
        <p>Total Access Count: {access_count}</p>
        <div class="recent-activity">
            <h4>Recent Activity:</h4>
            <ul>
    """
    
    # Add recent activity items (XSS vulnerability)
    for activity in recent_activity[:5]:
        activity_html += f"""
            <li>{activity.get('access_time', 'unknown')} - 
                {activity.get('action', 'unknown')} from 
                {activity.get('ip_address', 'unknown')}</li>
        """
    
    activity_html += """
            </ul>
        </div>
        <script>
            // Activity analytics
            updateActivityMetrics('%s', %d);
        </script>
    </div>
    """ % (user_id, access_count)
    
    return activity_html

def format_analytics_response(user_details: Dict, security_summary: str, 
                             activity_report: str, user_id: str) -> Dict[str, Any]:
    """
    Format final analytics response - Transport Layer formatting
    Final processing before returning to entry layer
    """
    logger.info(f"Formatting analytics response for user: {user_id}")
    
    user_profile = user_details.get('user_profile', {})
    
    # Format user info with potential XSS
    user_info_html = f"""
    <div class="user-info">
        <h3>User: {user_profile.get('name', user_id)}</h3>
        <p>Email: {user_profile.get('email', 'N/A')}</p>
        <p>Role: {user_profile.get('role', 'user')}</p>
        <p>Member Since: {user_profile.get('created_date', 'unknown')}</p>
    </div>
    """
    
    analytics_response = {
        'user_id': user_id,
        'user_info': user_info_html,
        'security_summary': security_summary,
        'activity_log': activity_report,
        'generated_timestamp': datetime.now().isoformat()
    }
    
    return analytics_response