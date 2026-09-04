import socket

import pytest

from app.security.dast_validator import validate_dast_url
from app.security.runner import RunnerSecurityError


def test_dast_url_valid_http_and_https():
    """Valid allowed URLs."""
    allowed = ["localhost", "127.0.0.1", "staging-app", "*.internal"]
    url1 = validate_dast_url("http://staging-app:3000/api/v1", allowed_hosts=allowed)
    assert url1 == "http://staging-app:3000/api/v1"

    url2 = validate_dast_url("https://staging-app/test", allowed_hosts=allowed)
    assert url2 == "https://staging-app/test"

    url3 = validate_dast_url("http://service.internal:8080", allowed_hosts=allowed)
    assert url3 == "http://service.internal:8080/"


def test_dast_url_forbidden_schemes():
    forbidden = [
        "file:///etc/passwd",
        "ftp://ftp.example.com/file",
        "gopher://gopher.example.com/",
        "data:text/plain;base64,SGVsbG8=",
        "javascript:alert(1)",
        "dict://dict.org",
        "ldap://ldap.internal",
    ]
    for bad_url in forbidden:
        with pytest.raises(RunnerSecurityError, match="Unsupported URL scheme"):
            validate_dast_url(bad_url)


def test_dast_url_missing_or_empty_hostname():
    with pytest.raises(RunnerSecurityError, match="must contain a valid hostname"):
        validate_dast_url("http://")
    with pytest.raises(RunnerSecurityError, match="cannot be empty"):
        validate_dast_url("")
    with pytest.raises(RunnerSecurityError, match="must be a non-empty string"):
        validate_dast_url(None)  # type: ignore


def test_dast_url_embedded_credentials():
    with pytest.raises(RunnerSecurityError, match="Embedded credentials"):
        validate_dast_url("http://admin:secret@staging-app:3000")


def test_dast_url_dangerous_characters():
    with pytest.raises(RunnerSecurityError, match="illegal or dangerous characters"):
        validate_dast_url("http://staging-app;rm -rf /")
    with pytest.raises(RunnerSecurityError, match="illegal or dangerous characters"):
        validate_dast_url("http://staging-app`id`")
    with pytest.raises(RunnerSecurityError, match="illegal or dangerous characters"):
        validate_dast_url("http://staging-app$(whoami)")


def test_dast_url_blocked_metadata_ssrf_ips():
    metadata_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.170.2/v2/metadata",
        "http://100.100.100.200/latest/meta-data/",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
    ]
    for url in metadata_urls:
        with pytest.raises(RunnerSecurityError, match="blocked metadata|SSRF protection"):
            validate_dast_url(url, allowed_hosts=["*"])


def test_dast_url_ssrf_loopback_and_private_ranges():
    """Strict validation for loopback, RFC1918, link-local, IPv6."""
    wildcard = ["*"]

    # Loopback
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://127.0.0.1:8000/", allowed_hosts=wildcard)
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://127.0.0.2:8080/", allowed_hosts=wildcard)
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://[::1]:8000/", allowed_hosts=wildcard)

    # RFC1918 10.0.0.0/8
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://10.0.0.1:8080/api", allowed_hosts=wildcard)
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://10.255.255.255:8080/api", allowed_hosts=wildcard)

    # RFC1918 172.16.0.0/12
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://172.16.0.5:8000/api", allowed_hosts=wildcard)
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://172.31.255.254/api", allowed_hosts=wildcard)

    # RFC1918 192.168.0.0/16
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://192.168.1.1:8080/", allowed_hosts=wildcard)
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://192.168.254.254:8080/", allowed_hosts=wildcard)

    # Link-local 169.254.0.0/16
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://169.254.1.1/", allowed_hosts=wildcard)

    # IPv6 link-local
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://[fe80::1]/api", allowed_hosts=wildcard)


def test_dast_url_dns_rebinding_public_host_resolving_to_private(monkeypatch):
    """Public hostname resolving to private/loopback is blocked (DNS rebinding / SSRF)."""
    def mock_getaddrinfo(host, port, **kwargs):
        if host in ("evil.example.com", "app.mycompany.com"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        if host == "rebind.internal.attacker.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", port))]
        if host == "rfc10.attacker.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]
        if host == "metadata.attacker.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    # Blocked even with wildcard allowlist
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://evil.example.com/admin", allowed_hosts=["*"])

    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://rebind.internal.attacker.com/status", allowed_hosts=["*"])

    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://rfc10.attacker.com/", allowed_hosts=["*"])

    with pytest.raises(RunnerSecurityError, match="blocked metadata|SSRF protection"):
        validate_dast_url("http://metadata.attacker.com/", allowed_hosts=["*"])

    # Blocked even if public domain is in allowed_hosts (rebinding protection)
    with pytest.raises(RunnerSecurityError, match="SSRF protection"):
        validate_dast_url("http://app.mycompany.com/api", allowed_hosts=["app.mycompany.com"])


def test_dast_url_allowed_host_and_internal_exemptions():
    """Explicit internal targets in allowed_hosts are permitted for testing."""
    assert (
        validate_dast_url("http://localhost:8000/api", allowed_hosts=["localhost"])
        == "http://localhost:8000/api"
    )
    assert (
        validate_dast_url("http://127.0.0.1:8000/api", allowed_hosts=["127.0.0.1"])
        == "http://127.0.0.1:8000/api"
    )
    assert (
        validate_dast_url("http://[::1]:8000/api", allowed_hosts=["::1"])
        == "http://[::1]:8000/api"
    )
    assert (
        validate_dast_url("http://staging-app:3000/", allowed_hosts=["staging-app"])
        == "http://staging-app:3000/"
    )


def test_dast_url_allowed_public_hostname(monkeypatch):
    """Allowed public host resolving to valid public IP is accepted."""
    def mock_getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    res = validate_dast_url("https://example.com/api", allowed_hosts=["example.com"])
    assert res == "https://example.com/api"


def test_dast_url_host_allowlist_enforcement():
    allowed = ["staging-app", "127.0.0.1", "*.internal"]

    # Allowed
    assert validate_dast_url("http://staging-app:8000", allowed_hosts=allowed) == "http://staging-app:8000/"
    assert validate_dast_url("http://api.internal:8000", allowed_hosts=allowed) == "http://api.internal:8000/"

    # Disallowed host
    with pytest.raises(RunnerSecurityError, match="not in the allowed DAST hosts"):
        validate_dast_url("http://malicious-external-site.com", allowed_hosts=allowed)

    with pytest.raises(RunnerSecurityError, match="not in the allowed DAST hosts"):
        validate_dast_url("http://8.8.8.8", allowed_hosts=allowed)


def test_dast_url_normalization():
    # Canonicalize port 80 for http
    res = validate_dast_url("HTTP://STAGING-APP:80/api/v1/", allowed_hosts=["staging-app"])
    assert res == "http://staging-app/api/v1/"

    # Canonicalize port 443 for https
    res = validate_dast_url("HTTPS://STAGING-APP:443/test", allowed_hosts=["staging-app"])
    assert res == "https://staging-app/test"

    # Strip fragments
    res = validate_dast_url("http://staging-app:3000/path#fragment", allowed_hosts=["staging-app"])
    assert res == "http://staging-app:3000/path"
