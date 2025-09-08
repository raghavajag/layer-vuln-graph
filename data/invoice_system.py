# Invoice Management - IDOR Vulnerability Demonstration
# Shows secure vs insecure patterns for the same functionality

import sqlite3
import sys
sys.path.append('..')

class InvoiceRepository:
    """Data access layer for invoices"""
    
    def __init__(self, db_path="invoices.db"):
        self.db_path = db_path
        
    def get_invoice_data(self, invoice_id):
        """VULNERABLE SINK: Template injection in invoice display"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # VULNERABILITY: SQL injection and template injection
        query = f"SELECT id, user_id, amount, description FROM invoices WHERE id = {invoice_id}"
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            # VULNERABILITY: Template injection sink
            template = f"<h2>Invoice #{result[0]} - Amount: ${result[2]}</h2><p>Description: {result[3]}</p>"
            from flask import render_template_string
            return render_template_string(template)
        
        conn.close()
        return result

class InvoiceService:
    """Core service for invoice operations - INSECURE PATH"""
    
    def __init__(self):
        self.repo = InvoiceRepository()
        
    def get_invoice(self, invoice_id):
        """Gets invoice without ownership check - VULNERABLE TRANSPORT"""
        # No ownership verification - direct call to repository
        return self.repo.get_invoice_data(invoice_id)

class UserInvoiceService:
    """User-scoped invoice service - SECURE PATH"""
    
    def __init__(self):
        self.repo = InvoiceRepository()
        
    def get_user_invoices(self, user_id, invoice_id):
        """Gets invoices with ownership check - SECURE TRANSPORT"""
        # First check ownership
        if self.check_invoice_ownership(user_id, invoice_id):
            return self.repo.get_invoice_data(invoice_id)
        else:
            return {"error": "Access denied: Invoice not owned by user"}
    
    def check_invoice_ownership(self, user_id, invoice_id):
        """Security control: Verifies invoice ownership"""
        conn = sqlite3.connect(self.repo.db_path)
        cursor = conn.cursor()
        
        # Verify the invoice belongs to the requesting user
        query = f"SELECT COUNT(*) FROM invoices WHERE id = {invoice_id} AND user_id = {user_id}"
        cursor.execute(query)
        count = cursor.fetchone()[0]
        
    def export_invoice_report(self, user_id, report_format="csv"):
        """VULNERABLE SINK: Command injection in report export"""
        # Get user invoices
        invoices = self.get_all_user_invoices(user_id)
        
        # VULNERABILITY: Command injection through subprocess
        export_cmd = f"python3 /opt/export_tool.py --user {user_id} --format {report_format} --output /tmp/report_{user_id}.{report_format}"
        import subprocess
        result = subprocess.run(export_cmd, shell=True, capture_output=True, text=True)
        
        return {"status": "export_complete", "output": result.stdout}

class InvoiceAPIController:
    """API controller with both secure and insecure endpoints"""
    
    def __init__(self):
        self.invoice_service = InvoiceService()
        self.user_invoice_service = UserInvoiceService()
    
    # ENTRY POINT 1: Direct invoice access - VULNERABLE
    def get_invoice_by_id_endpoint(self, invoice_id):
        """VULNERABLE: Direct access to any invoice by ID"""
        # ATTACK PATH: entry_get_by_id -> transport_invoice_service -> sink_get_invoice_data
        return self.invoice_service.get_invoice(invoice_id)
    
    # ENTRY POINT 2: User-scoped invoice access - SECURE  
    def get_user_invoice_endpoint(self, user_id, invoice_id):
        """SECURE: User-scoped invoice access"""
        # SECURE PATH: entry_get_for_user -> transport_user_service -> security_check_ownership -> transport_invoice_service -> sink_get_invoice_data
        return self.user_invoice_service.get_user_invoices(user_id, invoice_id)
