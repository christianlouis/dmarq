import re
import socket
from typing import Dict, Tuple, Union, Optional


def validate_domain(domain_name: str) -> Tuple[bool, Optional[str]]:
    """
    Validates a domain name for format and resolvability.
    
    Args:
        domain_name: The domain name to validate
        
    Returns:
        Tuple containing (is_valid, error_message)
        - is_valid: Boolean indicating if domain is valid
        - error_message: String with error message if not valid, None if valid
    """
    # Check for empty domain
    if not domain_name:
        return False, "Domain name cannot be empty"
    
    # Check domain format with regex
    # This regex allows domain names with alphanumeric characters, hyphens,
    # and periods as separators. It enforces proper domain structure.
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
    if not re.match(domain_pattern, domain_name):
        return False, "Invalid domain format"
    
    # Check if domain exists by attempting to resolve DNS
    try:
        socket.gethostbyname(domain_name)
        return True, None
    except socket.gaierror:
        # We could consider this valid if we don't require DNS resolution,
        # but since DMARC requires valid DNS, we'll mark it as warning
        return False, "Domain could not be resolved (DNS lookup failed)"


def validate_domain_config(domain_data: Dict) -> Dict[str, Union[bool, str]]:
    """
    Validates domain configuration data for creating or updating domains.
    
    Args:
        domain_data: Dictionary with domain configuration
        
    Returns:
        Dictionary with validation results containing:
        - valid: Boolean indicating if configuration is valid
        - errors: Dict of field-specific errors
    """
    errors = {}
    
    # Validate domain name
    if "name" in domain_data:
        is_valid, error_msg = validate_domain(domain_data["name"])
        if not is_valid:
            errors["name"] = error_msg
    else:
        errors["name"] = "Domain name is required"
    
    # Validate description (optional but with max length)
    if "description" in domain_data and domain_data["description"]:
        if len(domain_data["description"]) > 255:
            errors["description"] = "Description is too long (max 255 characters)"
    
    # Return validation results
    return {
        "valid": len(errors) == 0,
        "errors": errors
    }