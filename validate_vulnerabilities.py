#!/usr/bin/env python3
"""
Vulnerability Validation Script
Quick check to validate the vulnerability patterns are in place
"""

import os
import sys

def check_file_exists(filepath, description):
    """Check if a file exists"""
    if os.path.exists(filepath):
        print(f"✓ {description}: {filepath}")
        return True
    else:
        print(f"✗ {description}: {filepath} NOT FOUND")
        return False

def count_vulnerabilities_in_file(filepath, patterns):
    """Count vulnerability patterns in a file"""
    if not os.path.exists(filepath):
        return 0
    
    count = 0
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            for pattern in patterns:
                count += content.count(pattern)
    except Exception as e:
        print(f"  Warning: Could not read {filepath}: {e}")
        return 0
    
    return count

def main():
    print("=" * 70)
    print("VULNERABILITY CODEBASE VALIDATION")
    print("=" * 70)
    print()
    
    base_path = os.path.dirname(os.path.abspath(__file__))
    
    # Check core files exist
    print("1. Checking Core Files:")
    print("-" * 70)
    files_to_check = [
        ("repos/invoice_repo.py", "SQL Injection Repository"),
        ("services/extended_services.py", "Command Injection Services"),
        ("services/invoice_service.py", "Invoice Service"),
        ("routes/vulnerability_routes.py", "Vulnerability Routes"),
        ("routes/invoice_routes.py", "Invoice Routes"),
        ("app.py", "Main Application"),
        ("db_init.py", "Database Initialization"),
        ("utils/data_formatter.py", "Data Formatter"),
        ("README.md", "Documentation"),
        ("config.json", "Configuration"),
        ("requirements.txt", "Dependencies"),
        ("VULNERABILITY_SUMMARY.md", "Vulnerability Summary")
    ]
    
    all_exist = True
    for filepath, description in files_to_check:
        full_path = os.path.join(base_path, filepath)
        if not check_file_exists(full_path, description):
            all_exist = False
    
    print()
    
    # Count vulnerability patterns
    print("2. Counting Vulnerability Patterns:")
    print("-" * 70)
    
    vulnerability_checks = [
        {
            "file": "repos/invoice_repo.py",
            "patterns": ["f\"SELECT", "cursor.execute(query)", "CRITICAL:", "GOOD TO FIX:", "DEAD CODE:"],
            "name": "SQL Injection Patterns"
        },
        {
            "file": "services/extended_services.py",
            "patterns": ["subprocess", "os.system", "shell=True", "CRITICAL:", "DEAD CODE:"],
            "name": "Command Injection Patterns"
        },
        {
            "file": "routes/vulnerability_routes.py",
            "patterns": ["render_template_string", "XSS", "CRITICAL:", "PROTECTED:"],
            "name": "XSS/Template Injection Patterns"
        },
        {
            "file": "app.py",
            "patterns": ["render_template_string", "subprocess", "CRITICAL:", "DEAD CODE:"],
            "name": "Main App Vulnerabilities"
        },
        {
            "file": "db_init.py",
            "patterns": ["f\"SELECT", "f\"UPDATE", "f\"DELETE", "CRITICAL:", "DEAD CODE:"],
            "name": "Database Operation Vulnerabilities"
        }
    ]
    
    for check in vulnerability_checks:
        filepath = os.path.join(base_path, check["file"])
        count = count_vulnerabilities_in_file(filepath, check["patterns"])
        print(f"  {check['name']}: {count} patterns found in {check['file']}")
    
    print()
    
    # Summary statistics
    print("3. Vulnerability Category Summary:")
    print("-" * 70)
    
    # Count function definitions in key files
    def count_functions(filepath, prefix="def "):
        if not os.path.exists(filepath):
            return 0
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return sum(1 for line in f if line.strip().startswith(prefix))
        except:
            return 0
    
    sql_functions = count_functions(os.path.join(base_path, "repos/invoice_repo.py"))
    service_functions = count_functions(os.path.join(base_path, "services/extended_services.py"))
    route_functions = count_functions(os.path.join(base_path, "routes/vulnerability_routes.py"))
    
    print(f"  SQL Functions in invoice_repo.py: {sql_functions}")
    print(f"  Service Functions in extended_services.py: {service_functions}")
    print(f"  Route Functions in vulnerability_routes.py: {route_functions}")
    
    print()
    
    # Expected counts
    print("4. Expected Vulnerability Counts:")
    print("-" * 70)
    print("  Critical Vulnerabilities: 16")
    print("  Good to Fix Vulnerabilities: 13")
    print("  Protected Patterns: 9")
    print("  Dead Code Functions: 9")
    print("  Total Patterns: 47")
    
    print()
    
    # Final status
    print("=" * 70)
    if all_exist:
        print("✓ VALIDATION PASSED - All files present")
        print("✓ Codebase ready for PR review system testing")
    else:
        print("✗ VALIDATION FAILED - Some files missing")
        print("✗ Please check the file structure")
    print("=" * 70)
    print()
    print("Next Steps:")
    print("1. Review VULNERABILITY_SUMMARY.md for detailed vulnerability listing")
    print("2. Check README.md for comprehensive documentation")
    print("3. Run your PR review system against this codebase")
    print("4. Validate the AI detects all critical vulnerabilities")
    print("5. Ensure false positives (protected patterns) are not flagged")
    print("6. Verify dead code is properly identified")
    print()

if __name__ == "__main__":
    main()
