"""DAST target_url security validation and normalization.

Enforces strict SSRF protection, protocol whitelisting, host allowlisting,
credential stripping, and URL canonicalization before passing to DAST scanners.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import socket
from urllib.parse import urlparse, urlunparse

from app.security.runner import RunnerSecurityError

logger = logging.getLogger(__name__)

# Only standard HTTP/HTTPS schemes are permitted for DAST scans.
ALLOWED_SCHEMES = frozenset({"http", "https"})

# Characters forbidden in target URLs to prevent header/command injection.
FORBIDDEN_CHARS = frozenset(["\x00", ";", "|", "`", "$", "\n", "\r", "<", ">", "\"", "'", " "])
BLOCKED_METADATA_IPS = frozenset(
    {
        "169.254.169.254",  # AWS/GCP/Azure metadata
        "169.254.170.2",  # AWS ECS task metadata
        "100.100.100.200",  # Alibaba metadata
        "fd00:ec2::254",  # AWS IPv6 metadata
        "::ffff:169.254.169.254",
    }
)

# Default allowed hosts for development and containerized testing
DEFAULT_ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    "::1",
    "api",
    "staging-app",
    "app",
    "web",
    "testserver",
    "test-app",
    "*.internal",
    "*.local",
    "*.test",
]

# Explicit internal patterns that qualify as authorized internal targets when listed in allowlist
INTERNAL_PATTERNS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "api",
        "staging-app",
        "app",
        "web",
        "testserver",
        "test-app",
    }
)


def is_host_allowed(host: str, allowed_patterns: list[str]) -> bool:
    """Check if host matches any allowed pattern (exact or wildcard)."""
    host_lower = host.lower().strip()
    for pattern in allowed_patterns:
        pattern_lower = pattern.lower().strip()
        if pattern_lower == "*":
            return True
        if fnmatch.fnmatch(host_lower, pattern_lower):
            return True
        if host_lower == pattern_lower:
            return True
    return False


def is_ip_restricted(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if address falls into restricted SSRF ranges:
    loopback, RFC1918 private, link-local, unspecified, multicast, reserved, cloud metadata.
    """
    if ip_obj.version == 6 and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    ip_str = str(ip_obj)
    if ip_str in BLOCKED_METADATA_IPS:
        return True

    return bool(
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_unspecified
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or not ip_obj.is_global
    )


def is_authorized_internal_target(hostname: str, allowed_patterns: list[str]) -> bool:
    """Check if hostname is explicitly authorized as an internal target in allowed_patterns."""
    h_lower = hostname.lower().strip()
    for pattern in allowed_patterns:
        p_lower = pattern.lower().strip()
        if p_lower == "*":
            continue
        if p_lower in INTERNAL_PATTERNS and (h_lower == p_lower or fnmatch.fnmatch(h_lower, p_lower)):
            return True
        if (p_lower.endswith(".internal") or p_lower.endswith(".local") or p_lower.endswith(".test")) and fnmatch.fnmatch(h_lower, p_lower):
            return True
        if (
            h_lower.endswith(".internal")
            or h_lower.endswith(".local")
            or h_lower.endswith(".test")
        ) and (fnmatch.fnmatch(h_lower, p_lower) or p_lower == h_lower):
            return True
        # If pattern is an explicit literal IP equal to target hostname
        if p_lower == h_lower:
            try:
                ip_p = ipaddress.ip_address(p_lower)
                if is_ip_restricted(ip_p):
                    return True
            except ValueError:
                pass
    return False


def resolve_and_validate_host(
    hostname: str,
    port: int | None = None,
    allowed_hosts: list[str] | None = None,
    enforce_allowlist: bool = True,
    allow_internal: bool = False,
) -> None:
    """Resolve hostname and validate both textual host and all resolved addresses."""
    effective_allowed = allowed_hosts if allowed_hosts is not None else DEFAULT_ALLOWED_HOSTS

    if enforce_allowlist and not is_host_allowed(hostname, effective_allowed):
        raise RunnerSecurityError(
            f"Target host {hostname!r} is not in the allowed DAST hosts policy: {effective_allowed}"
        )

    explicitly_allowed_internal = allow_internal or (
        enforce_allowlist and is_authorized_internal_target(hostname, effective_allowed)
    )

    resolved_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        # Check if hostname is already a literal IP
        ip = ipaddress.ip_address(hostname)
        resolved_ips.append(ip)
    except ValueError:
        # Resolve hostname to IPv4/IPv6 addresses
        try:
            addr_info = socket.getaddrinfo(hostname, port or 80, type=socket.SOCK_STREAM)
            resolved_ips = [ipaddress.ip_address(addr[4][0]) for addr in addr_info]
        except socket.gaierror as exc:
            if explicitly_allowed_internal:
                # Docker service names might not resolve outside container network during offline tests
                return
            raise RunnerSecurityError(
                f"Target host {hostname!r} cannot be resolved: {exc}"
            ) from exc

    for ip_addr in resolved_ips:
        if str(ip_addr) in BLOCKED_METADATA_IPS:
            raise RunnerSecurityError(
                f"Target host {hostname!r} resolves to blocked metadata IP {ip_addr} (SSRF protection)"
            )
        if is_ip_restricted(ip_addr) and not explicitly_allowed_internal:
            raise RunnerSecurityError(
                f"Target host {hostname!r} resolves to restricted IP {ip_addr} (SSRF protection)"
            )


def validate_dast_url(
    target_url: str,
    allowed_hosts: list[str] | None = None,
    enforce_allowlist: bool = True,
    allow_internal: bool = False,
) -> str:
    """Validate and normalize target_url for DAST scanning.

    Raises RunnerSecurityError for invalid, dangerous, or unauthorized URLs.
    Returns normalized canonical URL.
    """
    if not isinstance(target_url, str):
        raise RunnerSecurityError("target_url must be a non-empty string")

    stripped = target_url.strip()
    if not stripped:
        raise RunnerSecurityError("target_url cannot be empty")

    try:
        parsed = urlparse(stripped)
    except Exception as exc:
        raise RunnerSecurityError(f"Malformed URL: {exc}") from exc

    # Scheme validation
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise RunnerSecurityError(
            f"Unsupported URL scheme {parsed.scheme!r}. Only http:// and https:// are permitted."
        )

    # Hostname validation
    hostname = parsed.hostname
    if not hostname:
        raise RunnerSecurityError("target_url must contain a valid hostname or IP address")

    # Reject dangerous characters
    if any(c in FORBIDDEN_CHARS for c in stripped):
        raise RunnerSecurityError("target_url contains illegal or dangerous characters")

    hostname_lower = hostname.lower()

    # Reject embedded credentials
    if parsed.username or parsed.password:
        raise RunnerSecurityError("Embedded credentials in target_url are forbidden")

    # Resolve DNS and validate resolved IPs against SSRF restricted address spaces
    resolve_and_validate_host(
        hostname_lower,
        port=parsed.port,
        allowed_hosts=allowed_hosts,
        enforce_allowlist=enforce_allowlist,
        allow_internal=allow_internal,
    )

    # Port and host netloc normalization (preserving IPv6 brackets)
    port = parsed.port
    is_ipv6 = ":" in hostname_lower
    host_formatted = f"[{hostname_lower}]" if is_ipv6 else hostname_lower

    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host_formatted}:{port}"
    else:
        netloc = host_formatted

    # Path normalization
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    # Canonical URL reconstruction
    normalized = urlunparse(
        (
            scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            "",  # Strip fragment for security and consistency
        )
    )
    return normalized
