"""
Data Formatting Utilities
New utility module for data processing and formatting operations
"""

import json
import re
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, date
from decimal import Decimal


class DataFormatter:
    """
    NEW FEATURE: Comprehensive data formatting utility class
    Provides standardized formatting for various data types across the application
    """
    
    def __init__(self, default_locale: str = "en_US"):
        self.default_locale = default_locale
        self.date_formats = {
            "iso": "%Y-%m-%d",
            "us": "%m/%d/%Y",
            "eu": "%d/%m/%Y",
            "timestamp": "%Y-%m-%d %H:%M:%S"
        }
    
    def format_currency(self, amount: Union[int, float, Decimal], 
                       currency: str = "USD", 
                       precision: int = 2) -> str:
        """
        Format currency values with proper symbols and precision
        """
        try:
            # Convert to float for formatting
            amount_float = float(amount)
            
            # Currency symbols mapping
            symbols = {
                "USD": "$",
                "EUR": "€",
                "GBP": "£",
                "JPY": "¥"
            }
            
            symbol = symbols.get(currency.upper(), currency.upper())
            
            # Format with precision
            formatted = f"{amount_float:.{precision}f}"
            
            # Add thousand separators for large amounts
            if abs(amount_float) >= 1000:
                formatted = self._add_thousand_separators(formatted)
            
            return f"{symbol}{formatted}"
            
        except (ValueError, TypeError) as e:
            return f"Invalid amount: {amount}"
    
    def format_date(self, date_obj: Union[datetime, date, str], 
                   format_type: str = "iso") -> str:
        """
        Format dates according to specified format type
        """
        try:
            # Handle string inputs
            if isinstance(date_obj, str):
                # Try to parse common date formats
                date_obj = self._parse_date_string(date_obj)
            
            # Handle datetime vs date objects
            if isinstance(date_obj, datetime):
                if format_type == "timestamp":
                    return date_obj.strftime(self.date_formats["timestamp"])
                date_obj = date_obj.date()
            
            if isinstance(date_obj, date):
                format_string = self.date_formats.get(format_type, self.date_formats["iso"])
                return date_obj.strftime(format_string)
            
            return str(date_obj)
            
        except Exception as e:
            return f"Invalid date: {date_obj}"
    
    def format_phone_number(self, phone: str, country_code: str = "US") -> str:
        """
        Format phone numbers according to country standards
        """
        # Remove all non-digit characters
        digits_only = re.sub(r'\D', '', phone)
        
        if country_code.upper() == "US":
            if len(digits_only) == 10:
                return f"({digits_only[:3]}) {digits_only[3:6]}-{digits_only[6:]}"
            elif len(digits_only) == 11 and digits_only[0] == '1':
                return f"+1 ({digits_only[1:4]}) {digits_only[4:7]}-{digits_only[7:]}"
        
        # Default format for other countries
        if len(digits_only) > 6:
            return f"+{digits_only[:2]} {digits_only[2:5]} {digits_only[5:]}"
        
        return phone  # Return original if can't format
    
    def format_address(self, address_dict: Dict[str, str]) -> str:
        """
        Format address dictionary into a standardized string
        """
        components = []
        
        # Standard address components in order
        if address_dict.get('street'):
            components.append(address_dict['street'])
        
        # City, State ZIP format for US addresses
        city_state_zip = []
        if address_dict.get('city'):
            city_state_zip.append(address_dict['city'])
        if address_dict.get('state'):
            city_state_zip.append(address_dict['state'])
        if address_dict.get('zip_code'):
            city_state_zip.append(address_dict['zip_code'])
        
        if city_state_zip:
            components.append(', '.join(city_state_zip))
        
        if address_dict.get('country'):
            components.append(address_dict['country'])
        
        return '\n'.join(components)
    
    def format_json_response(self, data: Any, pretty: bool = False) -> str:
        """
        Format data as JSON with optional pretty printing
        """
        try:
            if pretty:
                return json.dumps(data, indent=2, default=self._json_serializer, ensure_ascii=False)
            return json.dumps(data, default=self._json_serializer, separators=(',', ':'))
        except TypeError as e:
            return json.dumps({"error": f"Serialization failed: {str(e)}"})
    
    def sanitize_filename(self, filename: str, max_length: int = 255) -> str:
        """
        Sanitize filename by removing or replacing invalid characters
        """
        # Remove or replace invalid characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        # Remove leading/trailing whitespace and dots
        sanitized = sanitized.strip('. ')
        
        # Truncate if too long
        if len(sanitized) > max_length:
            name, ext = self._split_filename_extension(sanitized)
            available_length = max_length - len(ext)
            sanitized = name[:available_length] + ext
        
        return sanitized or "unnamed_file"
    
    def format_file_size(self, size_bytes: int) -> str:
        """
        Format file size in human-readable format
        """
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB", "PB"]
        size = float(size_bytes)
        unit_index = 0
        
        while size >= 1024 and unit_index < len(size_names) - 1:
            size /= 1024
            unit_index += 1
        
        # Format with appropriate precision
        if unit_index == 0:
            return f"{int(size)} {size_names[unit_index]}"
        else:
            return f"{size:.1f} {size_names[unit_index]}"
    
    # ==================== PRIVATE HELPER METHODS ====================
    
    def _add_thousand_separators(self, number_str: str) -> str:
        """Add thousand separators to number string"""
        parts = number_str.split('.')
        integer_part = parts[0]
        
        # Add commas every three digits from right
        formatted_integer = ""
        for i, digit in enumerate(reversed(integer_part)):
            if i > 0 and i % 3 == 0:
                formatted_integer = "," + formatted_integer
            formatted_integer = digit + formatted_integer
        
        if len(parts) > 1:
            return f"{formatted_integer}.{parts[1]}"
        return formatted_integer
    
    def _parse_date_string(self, date_str: str) -> datetime:
        """Parse various date string formats"""
        formats_to_try = [
            "%Y-%m-%d",
            "%m/%d/%Y",
            "%d/%m/%Y",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S"
        ]
        
        for fmt in formats_to_try:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        raise ValueError(f"Unable to parse date: {date_str}")
    
    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for non-standard types"""
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif isinstance(obj, Decimal):
            return float(obj)
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)
    
    def _split_filename_extension(self, filename: str) -> tuple:
        """Split filename into name and extension parts"""
        if '.' in filename:
            parts = filename.rsplit('.', 1)
            return parts[0], '.' + parts[1]
        return filename, ""


# ==================== STANDALONE UTILITY FUNCTIONS ====================

def quick_format_currency(amount: float, currency: str = "USD") -> str:
    """Quick utility function for currency formatting"""
    formatter = DataFormatter()
    return formatter.format_currency(amount, currency)

def quick_format_date(date_obj: Union[datetime, str], format_type: str = "iso") -> str:
    """Quick utility function for date formatting"""
    formatter = DataFormatter()
    return formatter.format_date(date_obj, format_type)

def validate_and_format_email(email: str) -> Dict[str, Any]:
    """
    NEW FEATURE: Email validation and formatting
    """
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # Basic validation
    is_valid = bool(re.match(email_pattern, email))
    
    # Format (normalize)
    formatted_email = email.lower().strip() if is_valid else email
    
    # Extract domain for additional info
    domain = formatted_email.split('@')[1] if is_valid and '@' in formatted_email else None
    
    return {
        'is_valid': is_valid,
        'formatted': formatted_email,
        'domain': domain,
        'local_part': formatted_email.split('@')[0] if is_valid else None
    }

def format_api_response(data: Any, status: str = "success", message: str = None) -> Dict[str, Any]:
    """
    NEW FEATURE: Standardized API response formatting
    """
    response = {
        'status': status,
        'timestamp': datetime.now().isoformat(),
        'data': data
    }
    
    if message:
        response['message'] = message
    
    return response