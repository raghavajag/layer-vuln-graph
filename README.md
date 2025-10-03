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

- **Template Injection**: In logging utilities
- **SQL Injection**: In repository layer
- **Path Traversal**: In file operations
- **Input Validation**: Various bypass attempts

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