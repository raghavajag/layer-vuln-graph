# AI-SAST v4.2 Demo Codebase

This demo codebase contains **intentional security vulnerabilities** designed to test the AI-SAST v4.2 Hybrid Static+LLM Intelligence system.

## 🚨 **WARNING: CONTAINS INTENTIONAL VULNERABILITIES**
**DO NOT USE IN PRODUCTION - FOR TESTING PURPOSES ONLY**

## Architecture Overview

The demo follows the 4-layer security model used by AI-SAST v4.2:

```
🚪 Entry Layer    → Web endpoints, API routes (app.py)
⬇️
➡️ Transport Layer → Business logic, data processing (business_logic.py)  
⬇️
🛡️ Security Layer  → Authentication, validation (security_utils.py)
⬇️
🧪 Sink Layer     → Database operations, file I/O (database.py)
```

## Vulnerability Categories

### 1. SQL Injection Vulnerabilities

**High Priority Attack Paths:**

- **Entry → Sink**: `search_users_api()` → `search_users_in_database()`
  - Entry Point: `/api/user/search` POST endpoint
  - Vulnerable Function: `search_users_in_database()` in `database.py`
  - Impact: Database compromise via user search

- **Entry → Security → Sink**: `admin_user_detail()` → `get_user_details_for_admin()` → `fetch_user_by_id()`
  - Entry Point: `/admin/user/<user_id>` GET endpoint  
  - Bypass: Weak admin authentication in `verify_admin_access()`
  - Impact: Admin privilege escalation + database access

- **Entry → Transport → Security → Sink**: `add_comment_api()` → `process_comment_submission()` → `validate_comment_content()` → `store_comment()`
  - Entry Point: `/api/comments/add` POST endpoint
  - Weakness: Security validation allows bypassed content through
  - Impact: Stored SQL injection in comment system

### 2. Cross-Site Scripting (XSS) Vulnerabilities

**Reflected XSS:**
- **Entry → Transport → Sink**: `public_profile()` → `load_public_profile()` → `get_profile_content()`
  - Entry Point: `/public/profile?profile_name=<script>alert(1)</script>`
  - Impact: Immediate script execution in user browser

**Stored XSS:**
- **Comment System**: XSS stored via `store_comment()` and reflected via profile content
  - Attack Vector: Submit comment with script tags
  - Impact: Persistent script execution for all users viewing content

**DOM-based XSS (JavaScript):**
- `dashboard.js`: Multiple functions with unsafe `innerHTML` usage
- `api-client.ts`: Template injection in `renderUserTemplate()`

### 3. Additional Vulnerabilities

**Command Injection (Java):**
- `VulnerableUserController.exportUserData()` - MySQL command injection
- Impact: Server-side command execution

**Deserialization (Java):**
- `VulnerableUserController.importUserData()` - Unsafe object deserialization
- Impact: Remote code execution via malicious serialized objects

**Prototype Pollution (TypeScript):**
- `ApiClient.mergeDeep()` - Unsafe object merging
- Impact: JavaScript prototype chain manipulation

## Expected Static Analysis Results

The tree-sitter static analyzer should identify:

### Function Call Graphs:
```
app.py:search_users_api() 
  → business_logic.py:process_user_search_request()
    → database.py:search_users_in_database() [SINK - SQL Injection]

app.py:admin_user_detail()
  → security_utils.py:verify_admin_access() [SECURITY - Weak Auth]
  → business_logic.py:get_user_details_for_admin()
    → database.py:fetch_user_by_id() [SINK - SQL Injection]

app.py:add_comment_api()
  → business_logic.py:process_comment_submission()
    → security_utils.py:validate_comment_content() [SECURITY - Weak XSS Protection]
    → database.py:store_comment() [SINK - SQL Injection + Stored XSS]
```

### Layer Classification:
- **Entry Points (🚪)**: 4 Flask routes in `app.py`
- **Transport Functions (➡️)**: 8 business logic functions in `business_logic.py`
- **Security Functions (🛡️)**: 7 validation functions in `security_utils.py`
- **Sink Functions (🧪)**: 9 database/storage functions in `database.py`

## Expected LLM Analysis Results

The enhanced LLM should provide:

### Security Intelligence:
- **Risk Severity**: Critical for SQL injection with admin privileges
- **Attack Complexity**: Low for direct injection, Medium for security bypass
- **Business Impact**: High for data breach, Medium for XSS
- **Remediation**: Parameterized queries, input validation, output encoding

### Vulnerability Context:
- **OWASP Categories**: A03:2021 Injection, A07:2021 XSS
- **CWE Classifications**: CWE-89 (SQL Injection), CWE-79 (XSS)
- **Attack Vectors**: Web interface, API endpoints, admin panels

## Testing Commands

### Run AI-SAST v4.2 on Demo Codebase:
```bash
cd /path/to/simple
python -m app.main --code_directory ./demo_codebase --output_format json --llm_enabled
```

### Expected Performance:
- **Static Analysis**: <30 seconds for call graph construction
- **LLM Analysis**: <5 minutes for 15+ findings
- **Graph Generation**: <2 seconds for vulnerability graphs

### Expected Findings Count:
- **SQL Injection**: 8+ findings across multiple entry points
- **XSS**: 6+ findings (reflected, stored, DOM-based)
- **Other**: 4+ findings (command injection, deserialization, etc.)
- **Total**: 18+ vulnerabilities across 4 layers

## Attack Path Examples

### Critical Attack Path 1: Admin Privilege Escalation
```
1. Attacker calls /admin/user/1' UNION SELECT password FROM admin_users--
2. Weak auth in verify_admin_access() accepts 'Bearer admin123'
3. SQL injection in fetch_user_by_id() executes malicious query
4. Admin credentials exposed in response
```

### Critical Attack Path 2: Stored XSS to SQL Injection
```
1. Attacker submits comment: <script>steal_session()</script>' OR 1=1--
2. validate_comment_content() ineffectively removes only <script> tags
3. store_comment() executes SQL injection + stores XSS payload
4. XSS executes on victim browsers + database compromised
```

## Validation Criteria

### Static Analysis Accuracy:
- ✅ Correctly identifies all 4 layers (Entry, Transport, Security, Sink)
- ✅ Maps accurate function call relationships
- ✅ Detects backward traversal paths from sinks to entry points
- ✅ Identifies security controls and their effectiveness

### LLM Intelligence Quality:
- ✅ Provides accurate severity assessments
- ✅ Identifies real-world attack scenarios
- ✅ Suggests appropriate remediation strategies
- ✅ Classifies vulnerabilities by standard frameworks (OWASP, CWE)

### Hybrid System Integration:
- ✅ Static analysis provides accurate "what calls what"
- ✅ LLM provides meaningful "what does it do"
- ✅ Combined results show complete attack paths
- ✅ Vulnerability graphs visualize end-to-end risks

## Files Overview

| File | Layer | Language | Primary Vulnerabilities |
|------|-------|----------|------------------------|
| `app.py` | Entry 🚪 | Python | Entry points for SQL injection, XSS |
| `business_logic.py` | Transport ➡️ | Python | Data processing, propagation |
| `security_utils.py` | Security 🛡️ | Python | Weak authentication, insufficient validation |
| `database.py` | Sink 🧪 | Python | SQL injection, data exposure |
| `static/dashboard.js` | Client | JavaScript | DOM-based XSS, unsafe innerHTML |
| `static/api-client.ts` | Client | TypeScript | Prototype pollution, template injection |
| `VulnerableUserController.java` | Backend | Java | Command injection, deserialization |

This demo codebase provides comprehensive coverage of modern web application vulnerabilities across multiple languages and architectural layers, making it ideal for testing the AI-SAST v4.2 hybrid static+LLM intelligence system.# layer-vuln-graph
