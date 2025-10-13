# Demo Codebase - PR Review Testing System

## Overview

This is an enhanced Flask-based demo application designed to test AI-enabled PR review systems. The codebase contains various vulnerability patterns, business logic, API endpoints, and utility functions to generate comprehensive change reports and diagrams during PR reviews.

## Recent Updates (v1.2.0)

### 🆕 New Features Added

#### Analytics Endpoints
- **System Analytics API**: Monitor application metrics, error rates, and performance statistics
- **User Behavior Analytics**: Track user interaction patterns and security anomalies
- **Risk Assessment**: Calculate user risk scores based on behavior patterns

#### Enhanced Invoice Processing
- **Improved Validation**: Comprehensive input validation for invoice data
- **Error Handling**: Robust error handling with detailed logging
- **Status Management**: New invoice status update functionality
- **Audit Trail**: Complete audit logging for all invoice operations

#### Data Formatting Utilities
- **Currency Formatting**: Multi-currency support with proper symbols and precision
- **Date Formatting**: Flexible date formatting with multiple locale support
- **Address Formatting**: Standardized address formatting for various countries
- **File Operations**: File size formatting and filename sanitization
- **Email Validation**: Email format validation and normalization

### 📁 Project Structure

```
demo_codebase/
├── api_controller.py          # Enhanced API controllers with analytics
├── app.py                     # Flask route definitions
├── main.py                    # Main application entry point
├── config.json               # Application configuration (NEW)
├── requirements.txt          # Python dependencies (NEW)
├── README.md                 # This documentation (UPDATED)
├── data/
│   └── invoice_system.py     # Invoice data models
├── repos/
│   └── invoice_repo.py       # Data repository layer
├── routes/
│   ├── invoice_routes.py     # Invoice-specific routes
│   └── vulnerability_routes.py # Vulnerability testing routes
├── services/
│   ├── extended_services.py  # Extended service implementations
│   └── invoice_service.py    # Enhanced invoice business logic
└── utils/
    ├── logger.py             # Centralized logging utility
    └── data_formatter.py     # Data formatting utilities (NEW)
```

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Flask 2.3+

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python main.py
   ```

### Available Scripts

- `npm run start` - Start the application
- `npm run test` - Run test suite
- `npm run lint` - Run code linting
- `npm run format` - Format code with Black
- `npm run analytics` - Test analytics endpoints
- `npm run validate` - Test validation functions

## 📊 API Endpoints

### Analytics Endpoints (NEW)

#### System Analytics
```http
GET /api/analytics/system?time_range=24h
```
Returns system-wide metrics including:
- Request counts and error rates
- Response time statistics
- Most frequently accessed endpoints

#### User Behavior Analytics
```http
GET /api/analytics/user/{user_id}
```
Returns user-specific analytics:
- Login patterns and frequency
- API usage patterns
- Security events and risk scoring

### Invoice Endpoints (ENHANCED)

#### Get Invoice
```http
GET /api/invoice/{user_id}
```
Enhanced with validation and error handling.

#### Create Invoice (NEW)
```http
POST /api/invoice
```
Create new invoices with comprehensive validation.

#### Update Invoice Status (NEW)
```http
PUT /api/invoice/{invoice_id}/status
```
Update invoice status with audit logging.

## 🛡️ Security Features

- **Input Validation**: Comprehensive validation for all user inputs
- **Rate Limiting**: Configurable rate limiting for API endpoints
- **Audit Logging**: Complete audit trail for all operations
- **Error Handling**: Secure error handling that doesn't leak sensitive information

## 🔧 Configuration

The application uses `config.json` for configuration management:

```json
{
  "features": {
    "analytics_endpoints": { "enabled": true },
    "enhanced_validation": { "enabled": true },
    "data_formatting": { "enabled": true }
  },
  "security": {
    "enable_rate_limiting": true,
    "max_requests_per_minute": 60,
    "enable_audit_logging": true
  }
}
```

## 🧪 Testing PR Review System

This codebase is specifically designed to test AI-enabled PR review systems. The recent changes include:

1. **API Changes**: New analytics endpoints to test API change detection
2. **Business Logic**: Enhanced validation and processing logic
3. **Utility Functions**: New data formatting utilities
4. **Configuration**: New config files and dependency updates
5. **Documentation**: Comprehensive README updates

### Expected PR Review Outputs

When these changes are merged, the PR review system should detect:

- **New API endpoints** with proper categorization
- **Enhanced business logic** with security implications
- **New utility functions** and their potential impact
- **Configuration changes** and dependency updates
- **Documentation improvements** and completeness

## 🔍 Vulnerability Testing

The codebase contains intentional vulnerability patterns for testing:

### Critical Vulnerabilities (Must Fix)

#### SQL Injection
- **Location**: `repos/invoice_repo.py`
  - `repo_get_invoice_by_id()` - Direct SQL injection, no protection
  - `search_invoices_vulnerable()` - Public search with SQL injection
  - `get_user_by_username_sqli()` - Exposes sensitive data including password hashes
- **Location**: `db_init.py`
  - `get_user_data_vulnerable()` - Direct string concatenation
  - `search_users_by_role()` - Multiple parameter injection
  - `execute_custom_query()` - Table name injection
- **Impact**: Data breach, unauthorized access, data manipulation

#### Command Injection
- **Location**: `services/extended_services.py`
  - `ping_host()` - Direct command execution with user input
  - `execute_diagnostic()` - No validation or sanitization
  - `run_batch_script()` - Command injection via script parameters
- **Location**: `routes/vulnerability_routes.py`
  - `/ping` endpoint - Direct subprocess call
  - `/direct_command` endpoint - Arbitrary command execution
- **Location**: `app.py`
  - `/ping` route - Command injection through subprocess
- **Impact**: Remote code execution, system compromise

#### Template Injection & XSS
- **Location**: `routes/vulnerability_routes.py`
  - `/dashboard` - Template injection in welcome message
  - `/search` - XSS in search results
  - `/comment` - XSS in comment display
  - `/notification` - XSS in notification system
- **Location**: `app.py`
  - `/dashboard` - Template injection
  - `/comment` - XSS vulnerability
- **Impact**: Session hijacking, credential theft, defacement

#### Path Traversal & File Operations
- **Location**: `services/extended_services.py`
  - `upload_and_save_file()` - Path traversal + potential RCE
  - `get_file_by_path()` - Direct path traversal, no validation
- **Location**: `routes/vulnerability_routes.py`
  - `/upload_and_execute` - Critical file upload vulnerability
- **Impact**: Arbitrary file read/write, potential RCE

### Good to Fix Vulnerabilities (Lower Priority)

#### SQL Injection with Partial Protection
- **Location**: `repos/invoice_repo.py`
  - `authenticate_user()` - Partial sanitization, still vulnerable
  - `search_logs_sqli()` - Lower business impact (logging system)
  - `custom_sanitization_sqli()` - Incomplete sanitization
- **Location**: `db_init.py`
  - `update_user_role_vulnerable()` - Partial sanitization

#### Weak Validation & Cryptography
- **Location**: `services/extended_services.py`
  - `hash_password()` - Base64 instead of proper hashing
  - `validate_email()` - Overly simplistic regex
  - `generate_session_token()` - Predictable token generation
- **Impact**: Account compromise, weak authentication

#### File Operations with Weak Validation
- **Location**: `services/extended_services.py`
  - `read_user_file()` - Weak path traversal protection
  - `read_internal_file()` - Lower impact (internal network)
- **Impact**: Limited file access

#### XSS with Mitigating Factors
- **Location**: `routes/vulnerability_routes.py`
  - `/user_profile` - Requires authentication
  - `/rate_limited_endpoint` - Protected by WAF/rate limiting
- **Impact**: Limited due to protections

### Protected Patterns (False Positives)

These should NOT be flagged as vulnerabilities:

#### Properly Sanitized SQL
- `search_with_parameterized_query()` - Parameterized queries
- `get_invoice_secure()` - Properly parameterized
- `get_user_data_secure()` - Secure implementation
- `update_user_role_secure()` - Both parameters properly handled

#### Properly Escaped XSS
- `/render_sanitized` - HTML escaping with `html.escape()`
- `safe_file_read()` - Proper file path validation

#### Protected Command Execution
- `admin_execute_command()` - Protected by @staff_member_required decorator
- `/admin_debug` - Admin-only access

#### Business Logic Protection
- `safe_file_read()` - Whitelist of allowed extensions
- `/file_access_sanitized` - Multiple validation layers

### Dead Code Vulnerabilities (Should Not Be Flagged)

These functions are never called and should be classified as dead code:

- **Location**: `repos/invoice_repo.py`
  - `unused_sql_injection_function()`
  - `legacy_db_query_vulnerable()`
  - `deprecated_admin_query()` - Also contains hardcoded credentials
  
- **Location**: `services/extended_services.py`
  - `legacy_load_user_preferences()` - Unsafe deserialization
  - `deprecated_get_file()` - Path traversal
  - `unused_command_executor()` - Command injection
  - `legacy_db_connect()` - Hardcoded credentials
  - `another_dead_function()` - Command injection

- **Location**: `db_init.py`
  - `legacy_raw_query_executor()` - Raw SQL execution
  - `unused_admin_query()` - Hardcoded credentials
  - `deprecated_batch_delete()` - Unsafe batch operation

- **Location**: `app.py`
  - `dead_controller()`
  - `unused_vulnerable_function()`
  - `legacy_file_reader()`

### Vulnerability Categories Summary

| Category | Critical | Good to Fix | Protected | Dead Code |
|----------|----------|-------------|-----------|-----------|
| SQL Injection | 5 | 4 | 4 | 4 |
| Command Injection | 4 | 1 | 1 | 2 |
| XSS/Template Injection | 5 | 2 | 2 | 0 |
| Path Traversal | 2 | 2 | 2 | 1 |
| Weak Crypto/Auth | 0 | 4 | 0 | 2 |
| **Total** | **16** | **13** | **9** | **9** |

⚠️ **Note**: This is a demo application with intentional vulnerabilities for testing purposes only.

## 📈 Monitoring and Metrics

- **Performance Monitoring**: Response time tracking
- **Error Rate Monitoring**: Comprehensive error tracking
- **Security Monitoring**: Anomaly detection and risk assessment
- **Usage Analytics**: User behavior and API usage patterns

## 🤝 Contributing

This codebase is designed for testing PR review systems. When making changes:

1. Ensure changes are moderate and testable
2. Include both secure and potentially vulnerable patterns
3. Update documentation accordingly
4. Test analytics and validation features

## 📝 Changelog

### v1.3.0 (2025-10-13)
- **MAJOR UPDATE**: Comprehensive vulnerability testing suite added
- Added 16 critical vulnerabilities across SQL injection, command injection, XSS, and path traversal
- Added 13 "good to fix" vulnerabilities with partial protections
- Added 9 protected patterns to test false positive detection
- Added 9 dead code functions with vulnerabilities
- Enhanced `repos/invoice_repo.py` with multiple SQL injection patterns
- Enhanced `services/extended_services.py` with command injection and file operation vulnerabilities
- Enhanced `routes/vulnerability_routes.py` with XSS and template injection patterns
- Added `db_init.py` for database operations with various vulnerability patterns
- Updated comprehensive vulnerability documentation
- Added vulnerability categorization and severity classification

### v1.2.0 (2025-10-03)
- Added comprehensive analytics endpoints
- Enhanced invoice processing with validation
- Added data formatting utilities
- Introduced configuration management
- Updated documentation and dependencies
- Improved error handling and logging

### v1.1.0 (Previous)
- Basic invoice system
- Vulnerability testing framework
- Initial API structure

---

*This README serves as comprehensive documentation for the demo codebase and should help the PR review system generate accurate change reports and diagrams.*