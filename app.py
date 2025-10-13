# Flask-like application with various vulnerability patterns
from flask import Flask, request, render_template_string
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

# ==================== VULNERABLE ROUTES ====================

@app.route("/invoice/<user_id>")
def get_invoice_route(user_id):
    """GOOD TO FIX: Weak input validation"""
    if not user_id.isdigit():
        raise ValueError("bad id")
    return invoice_service_get(user_id)

@app.route("/search")
def search_invoices():
    """CRITICAL: SQL injection in search"""
    from repos.invoice_repo import search_invoices_vulnerable
    query = request.args.get('q', '')
    results = search_invoices_vulnerable(query)
    return {"results": results}

@app.route("/dashboard")
def dashboard_page():
    """CRITICAL: Template injection"""
    username = request.args.get('user', 'Guest')
    template = f"<h1>Dashboard for {username}</h1>"
    return render_template_string(template)

@app.route("/ping", methods=['POST'])
def ping_host():
    """CRITICAL: Command injection"""
    import subprocess
    host = request.form.get('host', 'localhost')
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result.decode()

@app.route("/file/<path:filename>")
def read_file_route(filename):
    """GOOD TO FIX: Path traversal with weak protection"""
    from services.extended_services import FileOperationsService
    file_service = FileOperationsService()
    content = file_service.read_user_file(filename)
    return content or "File not found"

@app.route("/comment")
def display_comment():
    """CRITICAL: XSS vulnerability"""
    comment = request.args.get('text', '')
    html = f"<div class='comment'>{comment}</div>"
    return render_template_string(html)

# ==================== DEAD CODE FUNCTIONS ====================

def dead_controller(user_id):
    """DEAD CODE: This function is never called"""
    return invoice_service_dead(user_id)

def unused_vulnerable_function():
    """DEAD CODE: Unused function with command injection"""
    import os
    cmd = request.args.get('cmd', '')
    return os.system(cmd)

def legacy_file_reader(path):
    """DEAD CODE: Unused path traversal"""
    with open(path, 'r') as f:
        return f.read()


# ==================== HELPER FUNCTIONS ====================

def invoice_service_get(user_id):
    """Helper to get invoice"""
    from repos.invoice_repo import repo_get_invoice_by_id
    return repo_get_invoice_by_id(user_id)

def invoice_service_dead(user_id):
    """DEAD CODE: Unused helper function"""
    from repos.invoice_repo import repo_get_invoice_by_id
    return repo_get_invoice_by_id(user_id)


if __name__ == '__main__':
    # Debug mode in production is also a security issue
    app.run(debug=True, host='0.0.0.0')
