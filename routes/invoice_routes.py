# Invoice API Routes
# Demonstrates IDOR vulnerability with secure vs insecure endpoints

from flask import Flask, request, jsonify
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from data.invoice_system import InvoiceAPIController
    from api_controller import APIController
except ImportError:
    # Fallback for testing
    InvoiceAPIController = None
    APIController = None

app = Flask(__name__)

class InvoiceRoutes:
    """Routes for invoice access - both secure and vulnerable patterns"""
    
    def __init__(self):
        self.controller = InvoiceAPIController()
        self.api_controller = APIController()  # NEW: Add analytics controller

    # ==================== NEW ANALYTICS ROUTES ====================
    
    def get_system_analytics(self):
        """NEW FEATURE: System analytics endpoint"""
        time_range = request.args.get('time_range', '24h')
        try:
            analytics_data = self.api_controller.get_system_analytics(time_range)
            return jsonify(analytics_data)
        except Exception as e:
            return jsonify({"error": "Analytics retrieval failed", "details": str(e)}), 500

    def get_user_analytics(self):
        """NEW FEATURE: User behavior analytics endpoint"""
        user_id = request.view_args.get('user_id')
        try:
            analytics_data = self.api_controller.get_user_behavior_analytics(user_id)
            return jsonify(analytics_data)
        except Exception as e:
            return jsonify({"error": "User analytics retrieval failed", "details": str(e)}), 500

    def get_invoice_by_id(self):
        """VULNERABLE ENDPOINT: Template injection in invoice display"""
        invoice_id = request.view_args.get('id', '')
        
        if not invoice_id:
            return jsonify({"error": "Invoice ID required"}), 400
            
        # VULNERABILITY: Template injection sink through invoice display
        result = self.controller.get_invoice_by_id_endpoint(invoice_id)
        
        # VULNERABILITY: Direct template rendering with user data
        if result:
            invoice_template = f"<div>Invoice #{invoice_id}: {result}</div>"
            from flask import render_template_string
            return render_template_string(invoice_template)
        
        return jsonify(result)
    
    def get_current_user_invoices(self):
        """SECURE ENDPOINT: User-scoped invoice access"""
        # Simulated user authentication 
        current_user_id = request.headers.get('X-User-ID', '')
        invoice_id = request.args.get('invoice_id', '')
        
        if not current_user_id or not invoice_id:
            return jsonify({"error": "User ID and Invoice ID required"}), 400
            
        # SECURE: Properly checks ownership before allowing access
        result = self.controller.get_user_invoice_endpoint(current_user_id, invoice_id)
        return jsonify(result)

# Flask route bindings
invoice_routes = InvoiceRoutes()

@app.route('/api/invoices/<id>', methods=['GET'])
def api_get_invoice_by_id(id):
    """VULNERABLE: Any user can access any invoice"""
    return invoice_routes.get_invoice_by_id()

@app.route('/api/me/invoices', methods=['GET'])
def api_get_user_invoices():
    """SECURE: User can only access their own invoices"""
    return invoice_routes.get_current_user_invoices()
