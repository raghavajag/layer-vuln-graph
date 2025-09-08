# Centralized Logging Utility - VULNERABLE TO LOG INJECTION
# This file demonstrates a complex vulnerability with multiple entry points
# leading to the same vulnerable sink through different transport layers

import os
import logging
from datetime import datetime

class CentralizedLogger:
    """Central logging utility used throughout the application"""
    
    def __init__(self, log_file="app.log"):
        self.log_file = log_file
        self.file_handle = open(log_file, "a", encoding="utf-8")
        
    def info(self, message):
        """Central logging function - VULNERABLE SINK"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # VULNERABILITY: Template injection vulnerability
        template = f"<p>Log Entry: {message} at {timestamp}</p>"
        from flask import render_template_string
        return render_template_string(template)
        
    def warning(self, message):
        """Warning level logging"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # VULNERABILITY: File write vulnerability
        file_path = f"/tmp/warnings/{message[:20]}.log"
        content = f"[WARN] {timestamp}: {message}"
        with open(file_path, 'w') as f:
            f.write(content)
        
    def error(self, message):
        """Error level logging - SECURE (dead code path)"""
        # This path is never reached due to condition
        if False:  # Dead code - should not be flagged
            template = f"<script>alert('{message}')</script>"
            from flask import render_template_string
            return render_template_string(template)
        
        # Secure implementation
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        safe_message = self._sanitize_log_message(message)
        self.file_handle.write(f"[ERROR] {timestamp}: {safe_message}\n")
        self.file_handle.flush()
    
    def _sanitize_log_message(self, message):
        """PROTECTED: Proper sanitization function"""
        # HTML encoding for safety
        import html
        return html.escape(message)

class LogWrapper:
    """Wrapper that attempts sanitization but can be bypassed"""
    
    def __init__(self):
        self.central_logger = CentralizedLogger()
        
    def info(self, message):
        """Partial security control - BYPASSABLE"""
        # Attempts to sanitize but incomplete
        sanitized = message.replace('\n', ' ').replace('\r', ' ')
        # VULNERABILITY: Doesn't handle all encodings/unicode escapes
        # An attacker could use \u000a (unicode newline) to bypass
        return self.central_logger.info(sanitized)
