"""Target validation: IP, hostname, CIDR."""

import ipaddress
import re
from typing import Optional


def is_valid_cidr(s: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 CIDR range."""
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def is_valid_ip(s: str) -> bool:
    """Check if string is a single IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# Relaxed hostname: letters, digits, hyphens, dots; not starting/ending with hyphen
_HOSTNAME_PATTERN = re.compile(
    r"^(?!-)[a-zA-Z0-9]([a-zA-Z0-9.-]{0,61}[a-zA-Z0-9])?$"
)


def is_valid_hostname(s: str) -> bool:
    """Check if string looks like a valid hostname (not IP)."""
    if not s or len(s) > 253:
        return False
    if is_valid_ip(s):
        return False  # we treat IPs separately
    return bool(_HOSTNAME_PATTERN.match(s))


def validate_target(target: str) -> Optional[str]:
    """
    Validate target (IP, hostname, or CIDR).
    Returns None if valid, or an error message if invalid.
    """
    target = (target or "").strip()
    if not target:
        return "Target cannot be empty."

    if is_valid_ip(target) or is_valid_cidr(target) or is_valid_hostname(target):
        return None
    return (
        "Invalid target. Use a single IP (e.g. 192.168.1.10), "
        "a hostname (e.g. example.com), or a CIDR range (e.g. 192.168.1.0/24)."
    )


def validate_target_list(target_list_str: str) -> Optional[str]:
    """
    Validate a space-separated list of targets (IPs or hostnames).
    Returns None if all valid, or an error message if any invalid.
    """
    parts = (target_list_str or "").strip().split()
    if not parts:
        return "Target list cannot be empty."
    for t in parts:
        err = validate_target(t)
        if err:
            return f"Invalid target '{t}': {err}"
    return None
