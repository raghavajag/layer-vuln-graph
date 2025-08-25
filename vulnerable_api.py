#!/usr/bin/env python3
"""
Demo vulnerable API file for testing static analysis
"""

import sqlite3
from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

# Entry point functions (🚪 Entry Layer)
@app.route('/api/search', methods=['GET'])
def search_api(query):
    """API endpoint that searches data"""
    cleaned_query = validate_input(query)
    return search_database(cleaned_query)

def main():
    """Main entry point"""
    if len(sys.argv) > 1:
        user_input = sys.argv[1]
        process_user_input(user_input)
    app.run()

# Transport layer functions (➡️ Transport Layer)  
def process_user_input(user_data):
    """Process user input"""
    sanitized = sanitize_data(user_data)
    return execute_command(sanitized)

def search_database(query):
    """Search the database"""
    return execute_query(query)

# Security layer functions (🛡️ Security Layer)
def validate_input(data):
    """Validate input data"""
    if not data or len(data) > 1000:
        raise ValueError("Invalid input")
    return data

def sanitize_data(data):
    """Sanitize user data"""
    # Some sanitization logic
    return data.replace("'", "\'")

# Sink functions (🧪 Sink Layer)
def execute_query(query):
    """Execute SQL query - VULNERABLE SINK"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # VULNERABILITY: SQL injection via string concatenation
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return cursor.fetchall()

def execute_command(cmd):
    """Execute system command - VULNERABLE SINK"""
    # VULNERABILITY: Command injection
    subprocess.run(f"echo {cmd}", shell=True)

def render_template(template, data):
    """Render template - VULNERABLE SINK"""
    # VULNERABILITY: Server-side template injection
    return render_template_string(template, user_data=data)

if __name__ == "__main__":
    main()
