from typing import Dict, Any, Optional
from utils.logger import CentralizedLogger
from repos.invoice_repo import repo_get_invoice_by_id

logger = CentralizedLogger()

def invoice_service_get(user_id):
    """Enhanced invoice retrieval with validation and logging"""
    # Input validation
    if not _validate_user_id(user_id):
        logger.error(f"Invalid user ID format: {user_id}")
        raise ValueError("Invalid user ID format")
    
    try:
        # Log access attempt
        logger.info(f"Fetching invoice for user: {user_id}")
        
        result = repo_get_invoice_by_id(user_id)
        
        # Enhanced result processing
        if result:
            processed_result = _process_invoice_data(result)
            logger.info(f"Successfully retrieved invoice for user: {user_id}")
            return processed_result
        else:
            logger.warning(f"No invoice found for user: {user_id}")
            return {"error": "Invoice not found", "user_id": user_id}
            
    except Exception as e:
        logger.error(f"Error retrieving invoice for user {user_id}: {str(e)}")
        raise

def invoice_service_dead(user_id):
    """Legacy method - marked for deprecation"""
    logger.warning(f"Deprecated method called: invoice_service_dead for user {user_id}")
    return repo_get_invoice_by_id(user_id)

def create_invoice_service(user_id: str, invoice_data: Dict[str, Any]) -> Dict[str, Any]:
    """NEW FEATURE: Create new invoice with comprehensive validation"""
    # Validate input parameters
    validation_result = _validate_invoice_data(user_id, invoice_data)
    if not validation_result['is_valid']:
        logger.error(f"Invoice validation failed: {validation_result['errors']}")
        return {"error": "Validation failed", "details": validation_result['errors']}
    
    try:
        # Process and create invoice
        processed_data = _prepare_invoice_for_creation(invoice_data)
        logger.info(f"Creating new invoice for user: {user_id}")
        
        # Simulate invoice creation (would call repository layer)
        new_invoice = {
            "invoice_id": f"INV_{user_id}_{len(str(hash(str(invoice_data))))[:6]}",
            "user_id": user_id,
            "amount": processed_data.get('amount'),
            "status": "pending",
            "created_at": _get_current_timestamp()
        }
        
        logger.info(f"Successfully created invoice: {new_invoice['invoice_id']}")
        return {"success": True, "invoice": new_invoice}
        
    except Exception as e:
        logger.error(f"Failed to create invoice for user {user_id}: {str(e)}")
        return {"error": "Invoice creation failed", "details": str(e)}

def update_invoice_status(invoice_id: str, new_status: str) -> Dict[str, Any]:
    """NEW FEATURE: Update invoice status with audit logging"""
    if not _validate_invoice_id(invoice_id):
        return {"error": "Invalid invoice ID format"}
    
    if not _validate_status(new_status):
        return {"error": "Invalid status value"}
    
    try:
        logger.info(f"Updating invoice {invoice_id} status to: {new_status}")
        
        # Simulate status update
        update_result = {
            "invoice_id": invoice_id,
            "old_status": "pending",  # Would fetch from DB
            "new_status": new_status,
            "updated_at": _get_current_timestamp()
        }
        
        logger.info(f"Successfully updated invoice status: {invoice_id}")
        return {"success": True, "update": update_result}
        
    except Exception as e:
        logger.error(f"Failed to update invoice status {invoice_id}: {str(e)}")
        return {"error": "Status update failed", "details": str(e)}

# ==================== HELPER FUNCTIONS ====================

def _validate_user_id(user_id: str) -> bool:
    """Validate user ID format and constraints"""
    if not user_id or not isinstance(user_id, str):
        return False
    return user_id.isdigit() and len(user_id) > 0 and len(user_id) <= 10

def _validate_invoice_data(user_id: str, invoice_data: Dict[str, Any]) -> Dict[str, Any]:
    """Comprehensive validation of invoice data"""
    errors = []
    
    if not _validate_user_id(user_id):
        errors.append("Invalid user ID")
    
    if not invoice_data.get('amount') or not isinstance(invoice_data['amount'], (int, float)):
        errors.append("Invalid or missing amount")
    
    if invoice_data.get('amount', 0) <= 0:
        errors.append("Amount must be positive")
    
    if not invoice_data.get('description'):
        errors.append("Description is required")
    
    return {
        'is_valid': len(errors) == 0,
        'errors': errors
    }

def _validate_invoice_id(invoice_id: str) -> bool:
    """Validate invoice ID format"""
    return isinstance(invoice_id, str) and invoice_id.startswith('INV_') and len(invoice_id) > 4

def _validate_status(status: str) -> bool:
    """Validate invoice status values"""
    valid_statuses = ['pending', 'paid', 'cancelled', 'refunded']
    return status in valid_statuses

def _process_invoice_data(raw_data: Any) -> Dict[str, Any]:
    """Process and format invoice data for response"""
    if isinstance(raw_data, dict):
        return {
            **raw_data,
            "processed_at": _get_current_timestamp(),
            "format_version": "v2.0"
        }
    return {"data": raw_data, "processed_at": _get_current_timestamp()}

def _prepare_invoice_for_creation(invoice_data: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare invoice data for database insertion"""
    return {
        "amount": float(invoice_data.get('amount', 0)),
        "description": str(invoice_data.get('description', '')).strip(),
        "currency": invoice_data.get('currency', 'USD'),
        "metadata": invoice_data.get('metadata', {})
    }

def _get_current_timestamp() -> str:
    """Get current timestamp in ISO format"""
    import datetime
    return datetime.datetime.now().isoformat()
