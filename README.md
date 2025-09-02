# AI-SAST v4.2 Demo Codebase - Complex Vulnerability Scenarios

This demo codebase is specifically designed to test and demonstrate the full capabilities of the AI-SAST v4.2 hybrid analysis system. It showcases complex attack chains, security controls, and false positive scenarios that span multiple files and layers.

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   API Layer     │───▶│ Business Layer  │───▶│ Security Layer  │───▶│   Data Layer    │
│                 │    │                  │    │                 │    │                 │
│ • Entry Points  │    │ • Data Processing│    │ • Input Valida- │    │ • Database Ops │
│ • Route Handlers│    │ • Business Logic │    │   tion          │    │ • SQL Queries   │
│ • Parameter     │    │ • Call Chains    │    │ • Auth Controls │    │ • Data Access   │
│   Processing    │    │ • Transformations│    │ • Sanitization  │    │ • Persistence   │
└─────────────────┘    └──────────────────┘    └─────────────────┘    └─────────────────┘
```

## Vulnerability Scenarios

### 1. SQL Injection - User Search (COMPLEX ATTACK CHAINS)

**Entry Points:**
- `/api/users/search?q=<injection>` - Basic search
- `/api/users/details?id=<injection>` - Admin endpoint with auth

**Attack Paths:**
1. **Vulnerable Path:** `search_users_endpoint` → `search_users` → `_search_by_query` → `search_users_by_name`
2. **Also Vulnerable Path:** `get_user_details_endpoint` → `get_user_details` → `_get_admin_user_details` → `get_user_by_id`
3. **Partially Protected Path:** `search_products_endpoint` → `search_products` → `search_products` (sanitized)

**Security Controls:**
- `SQLInjectionDetector.detect_sql_injection_patterns()` - Logs but doesn't block
- `InputValidator.is_safe_search_term()` - Effective XSS prevention
- `AuthenticationManager.validate_token()` - Effective auth control

**False Positive Opportunities:**
- SQL injection detector is too sensitive and creates false positives
- Some paths are protected while others are vulnerable
- Complex call chains make static analysis challenging

### 2. XSS - Profile Display (MULTIPLE ENDPOINTS)

**Entry Points:**
- `/profile?username=<xss>` - Direct XSS vulnerability
- `/profile/safe?username=<xss>` - Properly encoded (secure)

**Attack Paths:**
1. **Vulnerable:** `public_profile_endpoint` → Direct HTML output
2. **Secure:** `safe_profile_endpoint` → `html.escape()` → Safe HTML output

### 3. Privilege Escalation - Admin Functions

**Entry Points:**
- `/admin/users/manage?action=delete&user_id=<id>`
- `/admin/users/manage?action=promote&user_id=<id>`

**Attack Paths:**
1. **Complex Chain:** `admin_user_management_endpoint` → `admin_user_management` → `delete_user`/`promote_user_to_admin`
2. **Security Control:** `validate_admin_token()` - Effective protection

## Key Testing Scenarios

### Complex Call Chains
- **User Search:** API → Business Logic → Security Check → Database (4 layers)
- **Admin Functions:** Auth → Business Logic → Multiple DB Calls (3+ layers)
- **Product Search:** Input Validation → Sanitization → Safe Database Query

### False Positive Detection
- SQL injection detector logs warnings but still processes requests
- Some endpoints have ineffective security controls
- Complex business logic creates ambiguous attack paths

### Multiple Attack Vectors
- String concatenation SQL injection
- Format string vulnerabilities
- Direct object references
- Privilege escalation attempts

## Expected AI-SAST Analysis Results

### Vulnerability 1: SQL Injection in User Search
**Expected Classification:** `must_fix`
**Attack Paths:** 2-3 complex paths from API to database
**Security Controls:** Partially effective (logging but not blocking)
**False Positive Elements:** Some paths are flagged but actually exploitable

### Vulnerability 2: XSS in Profile Display
**Expected Classification:** `must_fix`
**Attack Paths:** Direct path with no controls
**Security Controls:** None present
**False Positive Elements:** Similar endpoint is secure (shows proper mitigation exists)

### Vulnerability 3: Admin Privilege Escalation
**Expected Classification:** `good_to_fix` or `must_fix`
**Attack Paths:** Complex admin management chain
**Security Controls:** Strong authentication required
**False Positive Elements:** Requires admin privileges (may be acceptable risk)

## Testing Objectives

1. **Complex Graph Generation:** Generate multi-node graphs with 4+ layers
2. **False Positive Detection:** LLM should identify ineffective controls
3. **Attack Path Analysis:** Multiple paths per vulnerability
4. **Security Control Assessment:** Evaluate effectiveness of controls
5. **Hybrid Analysis Quality:** Combine static accuracy with LLM intelligence

## Running the Demo

```bash
cd demo_codebase
python -c "from api_layer import app; app.run(debug=True)"
```

## Files Structure

- `api_layer.py` - Entry points and API endpoints
- `business_layer.py` - Business logic and data processing
- `security_layer.py` - Security controls and validation
- `data_layer.py` - Database operations and data access
- `README.md` - This documentation

This codebase provides a realistic testing environment for the AI-SAST v4.2 hybrid analysis system, demonstrating complex real-world scenarios that require sophisticated vulnerability analysis.
