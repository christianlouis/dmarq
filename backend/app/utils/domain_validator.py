import html
import re
import socket
from typing import Dict, Optional, Tuple, Union


# Error codes for structured error handling
class DomainValidationError:
    """Domain validation error codes"""

    EMPTY = "empty"
    TOO_LONG = "too_long"
    INVALID_FORMAT = "invalid_format"
    INVALID_CHARACTERS = "invalid_characters"
    LABEL_TOO_LONG = "label_too_long"
    INVALID_LABEL = "invalid_label"
    DNS_RESOLUTION_FAILED = "dns_resolution_failed"


def _validate_domain_characters(
    domain_name: str,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Check a domain name for whitespace and suspicious characters."""
    if " " in domain_name or "\t" in domain_name or "\n" in domain_name:
        return (
            False,
            "Domain name cannot contain whitespace",
            DomainValidationError.INVALID_CHARACTERS,
        )
    if any(char in domain_name for char in ["<", ">", '"', "'", "\\", "|", ";", "&", "$", "`"]):
        return (
            False,
            "Domain name contains invalid characters",
            DomainValidationError.INVALID_CHARACTERS,
        )
    return True, None, None


def _validate_domain_labels(
    labels: list,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Check each DNS label for length and hyphen-placement rules."""
    for label in labels:
        if len(label) > 63:
            return (
                False,
                f"Domain label too long: '{label}' (max 63 characters per label)",
                DomainValidationError.LABEL_TOO_LONG,
            )
        if label.startswith("-") or label.endswith("-"):
            return (
                False,
                f"Domain label cannot start or end with hyphen: '{label}'",
                DomainValidationError.INVALID_LABEL,
            )
    return True, None, None


def validate_domain(  # pylint: disable=too-many-return-statements
    domain_name: str, check_dns: bool = True
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates a domain name for format and optionally resolvability.

    Args:
        domain_name: The domain name to validate
        check_dns: Whether to perform DNS resolution check (default: True)

    Returns:
        Tuple containing (is_valid, error_message, error_code)
        - is_valid: Boolean indicating if domain is valid
        - error_message: String with error message if not valid, None if valid
        - error_code: Error code constant for programmatic handling, None if valid
    """
    # Security: Check for empty or None domain
    if not domain_name:
        return False, "Domain name cannot be empty", DomainValidationError.EMPTY

    # Security: Check maximum length (DNS standard is 253 characters)
    if len(domain_name) > 253:
        return False, "Domain name too long (max 253 characters)", DomainValidationError.TOO_LONG

    # Security: Check for whitespace and suspicious characters
    char_ok, char_msg, char_code = _validate_domain_characters(domain_name)
    if not char_ok:
        return False, char_msg, char_code

    # Check domain format with regex
    # This regex allows domain names with alphanumeric characters, hyphens,
    # and periods as separators. It enforces proper domain structure.
    # Updated to be more strict and prevent potential attacks
    domain_pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    if not re.match(domain_pattern, domain_name.lower()):
        return False, "Invalid domain format", DomainValidationError.INVALID_FORMAT

    # Security: Check each label length (max 63 characters per label)
    labels = domain_name.split(".")
    label_ok, label_msg, label_code = _validate_domain_labels(labels)
    if not label_ok:
        return False, label_msg, label_code

    # Check if domain exists by attempting to resolve DNS (optional)
    if check_dns:
        try:
            socket.gethostbyname(domain_name)
        except socket.gaierror:
            # We could consider this valid if we don't require DNS resolution,
            # but since DMARC requires valid DNS, we'll mark it as warning
            return (
                False,
                "Domain could not be resolved (DNS lookup failed)",
                DomainValidationError.DNS_RESOLUTION_FAILED,
            )

    return True, None, None


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
        # Don't check DNS for domain config validation
        is_valid, error_msg, _ = validate_domain(domain_data["name"], check_dns=False)
        if not is_valid:
            errors["name"] = error_msg
    else:
        errors["name"] = "Domain name is required"

    # Validate description (optional but with max length)
    if "description" in domain_data and domain_data["description"]:
        if len(domain_data["description"]) > 500:
            errors["description"] = "Description is too long (max 500 characters)"
        # Security: Use html.escape to prevent XSS
        escaped = html.escape(domain_data["description"])
        if escaped != domain_data["description"]:
            errors["description"] = "Description contains potentially unsafe HTML content"

    # Return validation results
    return {"valid": len(errors) == 0, "errors": errors}
