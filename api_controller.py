"""
API Controller for Complex Attack Path Testing
Demonstrates various API patterns leading to vulnerable sinks and false positives
"""

import os
import json
from typing import Dict, List, Any, Optional
from flask import request, jsonify

from services.extended_services import (
    CentralizedLogger, 
    UserProfileService, 
    OrderManagementService,
    BackgroundSyncService
)
from data.invoice_system import InvoiceRepository, InvoiceService
from utils.logger import CentralizedLogger as UtilsLogger

class APIController:
    """
    Comprehensive API controller demonstrating:
    1. Complex vulnerable call chains
    2. False positive patterns (protected/sanitized/dead code)
    3. Multiple entry points to same sinks
    4. Cross-layer vulnerability propagation
    """
    
    def __init__(self):
        # Initialize all service layers
        self.profile_service = UserProfileService()
        self.order_service = OrderManagementService()
        self.sync_service = BackgroundSyncService()
        self.invoice_service = InvoiceService()
        
        # Initialize loggers
        self.central_logger = CentralizedLogger()
        self.utils_logger = UtilsLogger()
    
    # ==================== COMPLEX VULNERABLE PATHS ====================
    
    def handle_user_feedback(self, feedback_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        VULNERABLE: Multi-layer feedback processing with template injection
        Path: API → Validation → Processing → Service → Logger → Template Sink
        """
        # Layer 1: Basic validation (insufficient)
        if not feedback_data.get('message'):
            return {"error": "Message required"}
            
        # Layer 2: Content processing
        processed_feedback = self._process_feedback_content(feedback_data)
        
        # Layer 3: Service layer call (vulnerable)
        feedback_id = self._store_feedback_data(processed_feedback)
        
        # Layer 4: Response generation with template injection
        response_template = f"""
        <div class='feedback-response'>
            <h3>Thank you for your feedback!</h3>
            <p>Your message: {processed_feedback['message']}</p>
            <small>Feedback ID: {feedback_id}</small>
        </div>
        """
        
        # VULNERABLE SINK: Template injection
        from flask import render_template_string
        return {"html_response": render_template_string(response_template)}
    
    def handle_file_upload_processing(self, file_data: Dict[str, Any], user_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        VULNERABLE: File processing with command injection
        Path: API → File Validation → Metadata Processing → Command Execution
        """
        # Layer 1: File validation
        if not self._is_valid_file_upload(file_data):
            return {"error": "Invalid file upload"}
            
        # Layer 2: Metadata extraction
        file_metadata = self._extract_file_metadata(file_data, user_context)
        
        # Layer 3: File processing service
        processing_result = self._process_uploaded_file(file_metadata)
        
        # VULNERABLE SINK: Command injection in file processing
        processing_cmd = f"python3 /opt/file_processor.py --file '{file_metadata['filename']}' --user '{user_context['user_id']}'"
        import subprocess
        result = subprocess.run(processing_cmd, shell=True, capture_output=True, text=True)
        
        return {"status": "processed", "output": result.stdout}
    
    def handle_search_and_export(self, search_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        VULNERABLE: Search with export functionality leading to file write
        Path: API → Search Processing → Export Generation → File Write
        """
        # Layer 1: Search parameter processing
        processed_search = self._process_search_parameters(search_params)
        
        # Layer 2: Search execution
        search_results = self._execute_search_query(processed_search)
        
        # Layer 3: Export generation
        export_data = self._generate_export_data(search_results, search_params)
        
        # VULNERABLE SINK: File write with user-controlled path
        export_filename = f"search_results_{search_params.get('export_name', 'default')}.csv"
        export_path = f"/tmp/exports/{export_filename}"
        
        with open(export_path, 'w') as f:
            f.write(f"Search Results Export\n")
            f.write(f"Query: {search_params.get('query', '')}\n")
            f.write(f"Results: {len(search_results)} items\n")
            f.write(export_data)
        
        return {"export_path": export_path, "results_count": len(search_results)}
    
    # ==================== FALSE POSITIVE PATTERNS ====================
    
    def handle_secure_report_generation(self, report_params: Dict[str, Any], auth_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        PROTECTED: Secure report generation with proper validation
        Should be classified as false_positive_protected
        """
        # Strong authentication check
        if not self._verify_report_access_permission(auth_context):
            return {"error": "Unauthorized access", "code": 401}
        
        # Input sanitization
        sanitized_params = self._sanitize_report_parameters(report_params)
        
        # Secure report generation
        report_data = self._generate_secure_report(sanitized_params)
        
        # PROTECTED: Even though template is used, input is properly sanitized
        import html
        safe_title = html.escape(sanitized_params.get('title', 'Report'))
        template = f"<h1>Report: {safe_title}</h1><div>Generated securely</div>"
        
        from flask import render_template_string
        return {"report_html": render_template_string(template), "data": report_data}
    
    def handle_legacy_import_feature(self, import_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        DEAD CODE: Legacy import functionality that's never called
        Should be classified as false_positive_dead_code
        """
        # This feature is disabled and code is unreachable
        feature_enabled = False
        
        if feature_enabled:  # This condition is always False
            # DEAD CODE: Command injection in unreachable code
            import_cmd = f"python3 /legacy/import_tool.py --data '{import_data['raw_content']}'"
            import subprocess
            result = subprocess.run(import_cmd, shell=True, capture_output=True, text=True)
            return {"legacy_import": result.stdout}
        
        return {"error": "Legacy import feature is disabled"}
    
    def handle_admin_system_maintenance(self, maintenance_params: Dict[str, Any], admin_token: str) -> Dict[str, Any]:
        """
        PROTECTED: Administrative system maintenance with multiple security layers
        Should be classified as false_positive_protected
        """
        # Layer 1: Admin authentication
        if not self._verify_admin_token(admin_token):
            return {"error": "Invalid admin token"}
        
        # Layer 2: Permission verification
        if not self._check_maintenance_permissions(admin_token):
            return {"error": "Insufficient permissions for maintenance operations"}
        
        # Layer 3: Input validation and sanitization
        validated_params = self._validate_maintenance_parameters(maintenance_params)
        if not validated_params['is_valid']:
            return {"error": "Invalid maintenance parameters"}
        
        # PROTECTED: Command execution with proper controls
        maintenance_script = validated_params['safe_script_path']  # Pre-validated safe path
        import subprocess
        result = subprocess.run([
            '/usr/bin/python3', 
            maintenance_script,
            '--mode', validated_params['safe_mode']
        ], capture_output=True, text=True)  # No shell=True, uses list format
        
        return {"maintenance_status": "completed", "output": result.stdout}
    
    # ==================== HELPER METHODS ====================
    
    def _process_feedback_content(self, feedback_data: Dict[str, Any]) -> Dict[str, Any]:
        """Content processing layer - part of vulnerable path"""
        # Insufficient processing allows malicious content through
        processed = {
            'message': feedback_data.get('message', ''),
            'category': feedback_data.get('category', 'general'),
            'priority': feedback_data.get('priority', 'normal'),
            'processed_at': 'now()'
        }
        
        # Log processing (goes to vulnerable logger)
        self.utils_logger.info(f"Processing feedback: {processed['message']}")
        
        return processed
    
    def _store_feedback_data(self, feedback: Dict[str, Any]) -> str:
        """Data storage layer - continues vulnerable path"""
        # Generate feedback ID
        feedback_id = f"fb_{hash(feedback['message']) % 10000}"
        
        # Store through service layer (vulnerable)
        self.profile_service.update_profile(
            f"feedback_user_{feedback_id}",
            f"feedback@{feedback['category']}.com"
        )
        
        return feedback_id
    
    def _is_valid_file_upload(self, file_data: Dict[str, Any]) -> bool:
        """Basic file validation - insufficient"""
        return 'filename' in file_data and 'content' in file_data
    
    def _extract_file_metadata(self, file_data: Dict[str, Any], user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Metadata extraction - passes user input through"""
        return {
            'filename': file_data.get('filename', 'unknown'),
            'user_id': user_context.get('user_id', 'anonymous'),
            'upload_time': 'now()',
            'size': len(file_data.get('content', ''))
        }
    
    def _process_uploaded_file(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """File processing - logs through vulnerable path"""
        self.central_logger.info(f"Processing file: {metadata['filename']} for user: {metadata['user_id']}")
        return {"processing_status": "queued"}
    
    def _process_search_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Search parameter processing"""
        return {
            'query': params.get('query', ''),
            'filters': params.get('filters', {}),
            'sort_by': params.get('sort_by', 'relevance')
        }
    
    def _execute_search_query(self, search_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search execution"""
        # Simulate search results
        return [
            {"id": 1, "title": f"Result for {search_params['query']}"},
            {"id": 2, "title": f"Another match for {search_params['query']}"}
        ]
    
    def _generate_export_data(self, results: List[Dict[str, Any]], params: Dict[str, Any]) -> str:
        """Export data generation"""
        export_lines = []
        for result in results:
            export_lines.append(f"{result['id']},{result['title']}")
        return "\n".join(export_lines)
    
    # Protected function helpers
    
    def _verify_report_access_permission(self, auth_context: Dict[str, Any]) -> bool:
        """Strong permission verification"""
        return (auth_context.get('role') == 'admin' and 
                auth_context.get('permissions', {}).get('reports', False))
    
    def _sanitize_report_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Proper input sanitization"""
        import html
        return {
            'title': html.escape(str(params.get('title', 'Untitled'))[:100]),
            'filters': self._sanitize_dict(params.get('filters', {}))
        }
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Helper for deep sanitization"""
        import html
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[html.escape(key)] = html.escape(value)
            else:
                sanitized[html.escape(key)] = str(value)[:50]
        return sanitized
    
    def _generate_secure_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Secure report generation"""
        return {
            "report_title": params['title'],
            "generated_at": "now()",
            "secure": True
        }
    
    def _verify_admin_token(self, token: str) -> bool:
        """Strong admin token verification"""
        return (len(token) > 50 and 
                token.startswith('admin_') and 
                'verified_signature' in token)
    
    def _check_maintenance_permissions(self, token: str) -> bool:
        """Maintenance permission check"""
        return 'maintenance' in token and 'authorized' in token
    
    def _validate_maintenance_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive parameter validation"""
        allowed_scripts = ['/opt/maintenance/cleanup.py', '/opt/maintenance/backup.py']
        allowed_modes = ['safe', 'check', 'dry_run']
        
        script_path = params.get('script', '')
        mode = params.get('mode', '')
        
        return {
            'is_valid': script_path in allowed_scripts and mode in allowed_modes,
            'safe_script_path': script_path if script_path in allowed_scripts else allowed_scripts[0],
            'safe_mode': mode if mode in allowed_modes else 'safe'
        }
    
    # ==================== NEW ANALYTICS ENDPOINTS ====================
    
    def get_system_analytics(self, time_range: str = "24h") -> Dict[str, Any]:
        """
        NEW FEATURE: System analytics endpoint for monitoring
        Returns system metrics and usage statistics
        """
        import datetime
        from collections import defaultdict
        
        # Simulate analytics data collection
        metrics = {
            'requests_total': self._get_request_count(time_range),
            'error_rate': self._calculate_error_rate(time_range),
            'response_times': self._get_response_time_stats(time_range),
            'top_endpoints': self._get_top_endpoints(time_range),
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Log analytics access for audit trail
        self.central_logger.info(f"Analytics accessed for range: {time_range}")
        
        return {
            'status': 'success',
            'data': metrics,
            'time_range': time_range
        }
    
    def get_user_behavior_analytics(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        NEW FEATURE: User behavior analytics
        Analyzes user interaction patterns and potential security anomalies
        """
        if user_id and not self._validate_user_id(user_id):
            return {"error": "Invalid user ID format"}
            
        behavior_data = {
            'login_patterns': self._analyze_login_patterns(user_id),
            'api_usage': self._analyze_api_usage(user_id),
            'security_events': self._get_security_events(user_id),
            'risk_score': self._calculate_risk_score(user_id)
        }
        
        return {
            'status': 'success',
            'user_id': user_id or 'all_users',
            'analytics': behavior_data
        }
    
    # ==================== ANALYTICS HELPER METHODS ====================
    
    def _get_request_count(self, time_range: str) -> int:
        """Helper method to get request count for given time range"""
        # Simulate request counting logic
        base_count = 1000
        multiplier = {'1h': 0.1, '24h': 1.0, '7d': 7.0, '30d': 30.0}
        return int(base_count * multiplier.get(time_range, 1.0))
    
    def _calculate_error_rate(self, time_range: str) -> float:
        """Calculate error rate percentage"""
        # Simulate error rate calculation
        import random
        return round(random.uniform(0.5, 5.0), 2)
    
    def _get_response_time_stats(self, time_range: str) -> Dict[str, float]:
        """Get response time statistics"""
        import random
        return {
            'avg': round(random.uniform(100, 500), 2),
            'p95': round(random.uniform(500, 1000), 2),
            'p99': round(random.uniform(1000, 2000), 2)
        }
    
    def _get_top_endpoints(self, time_range: str) -> List[Dict[str, Any]]:
        """Get most frequently accessed endpoints"""
        return [
            {'endpoint': '/api/invoice', 'requests': 150, 'avg_response_time': 245.2},
            {'endpoint': '/api/user/profile', 'requests': 120, 'avg_response_time': 180.5},
            {'endpoint': '/api/analytics', 'requests': 85, 'avg_response_time': 320.1}
        ]
    
    def _validate_user_id(self, user_id: str) -> bool:
        """Validate user ID format"""
        return user_id.isdigit() and len(user_id) > 0
    
    def _analyze_login_patterns(self, user_id: Optional[str]) -> Dict[str, Any]:
        """Analyze user login patterns"""
        return {
            'frequent_login_times': ['09:00-10:00', '14:00-15:00'],
            'login_frequency': 'normal',
            'suspicious_locations': []
        }
    
    def _analyze_api_usage(self, user_id: Optional[str]) -> Dict[str, Any]:
        """Analyze API usage patterns"""
        return {
            'most_used_endpoints': ['/api/invoice', '/api/profile'],
            'usage_pattern': 'regular',
            'rate_limit_hits': 0
        }
    
    def _get_security_events(self, user_id: Optional[str]) -> List[Dict[str, Any]]:
        """Get security-related events"""
        return [
            {'event': 'failed_login', 'count': 2, 'last_occurrence': '2025-10-02T10:30:00Z'},
            {'event': 'suspicious_ip', 'count': 0, 'last_occurrence': None}
        ]
    
    def _calculate_risk_score(self, user_id: Optional[str]) -> Dict[str, Any]:
        """Calculate user risk score"""
        return {
            'score': 2.5,
            'level': 'low',
            'factors': ['normal_login_pattern', 'regular_api_usage']
        }
