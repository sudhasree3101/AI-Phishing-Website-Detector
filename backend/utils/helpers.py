import socket
import ipaddress
import urllib.parse
import re
import requests

BLOCKED_IP_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Cybersecurity-Phishing-Detector/1.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
}

def normalize_url(url: str) -> str:
    """Ensure URL has scheme and is stripped of spaces."""
    if not url:
        return ""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate URL format and check for SSRF vulnerabilities.
    Returns (is_valid, error_message).
    """
    normalized = normalize_url(url)
    try:
        parsed = urllib.parse.urlparse(normalized)
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL hostname."

        # Check for forbidden scheme
        if parsed.scheme not in ('http', 'https'):
            return False, "Only HTTP and HTTPS protocols are allowed."

        # Hostname check: block 'localhost', '.local', etc.
        hostname_lower = hostname.lower()
        if hostname_lower == 'localhost' or hostname_lower.endswith('.local'):
            return False, "Analysis of localhost or internal network hosts is blocked for security."

        # Check IP resolution for SSRF protection
        try:
            # Try parsing as IP address directly first
            ip_obj = ipaddress.ip_address(hostname_lower)
            for blocked in BLOCKED_IP_RANGES:
                if ip_obj in blocked:
                    return False, f"Access to private or loopback IP range ({hostname}) is blocked."
        except ValueError:
            # It's a hostname, resolve DNS records to verify resolved IP
            try:
                ip_list = socket.getaddrinfo(hostname, None)
                for res in ip_list:
                    resolved_ip = res[4][0]
                    ip_obj = ipaddress.ip_address(resolved_ip)
                    for blocked in BLOCKED_IP_RANGES:
                        if ip_obj in blocked:
                            return False, f"Domain resolves to blocked internal IP address ({resolved_ip})."
            except socket.gaierror:
                # DNS resolution failure will be handled gracefully later
                pass

        return True, ""
    except Exception as e:
        return False, f"URL validation failed: {str(e)}"

def safe_fetch_page(url: str, timeout: int = 5, max_bytes: int = 2 * 1024 * 1024) -> dict:
    """
    Safely fetch a webpage content with strict timeout, max size limit, and SSRF checks.
    """
    is_valid, err_msg = validate_url(url)
    if not is_valid:
        return {
            "success": False,
            "error": err_msg,
            "status_code": None,
            "content": "",
            "headers": {},
            "final_url": url,
            "redirects": []
        }

    normalized_url = normalize_url(url)

    try:
        session = requests.Session()
        session.max_redirects = 5
        
        response = session.get(
            normalized_url,
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            stream=True,
            verify=False  # Allow analyzing sites even with broken SSL certificates
        )

        redirect_chain = [r.url for r in response.history]

        # Read only up to max_bytes to prevent memory exhaustion / bomb attacks
        content_bytes = bytearray()
        for chunk in response.iter_content(chunk_size=4096):
            content_bytes.extend(chunk)
            if len(content_bytes) >= max_bytes:
                break

        # Decode content HTML cleanly
        try:
            content = content_bytes.decode(response.encoding or 'utf-8', errors='replace')
        except Exception:
            content = content_bytes.decode('utf-8', errors='replace')

        return {
            "success": True,
            "error": "",
            "status_code": response.status_code,
            "content": content,
            "headers": dict(response.headers),
            "final_url": response.url,
            "redirects": redirect_chain
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": "Connection timed out after 5 seconds.",
            "status_code": None,
            "content": "",
            "headers": {},
            "final_url": normalized_url,
            "redirects": []
        }
    except requests.exceptions.SSLError as e:
        return {
            "success": False,
            "error": f"SSL Error occurred: {str(e)}",
            "status_code": None,
            "content": "",
            "headers": {},
            "final_url": normalized_url,
            "redirects": []
        }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "error": "Failed to establish a connection to the target server.",
            "status_code": None,
            "content": "",
            "headers": {},
            "final_url": normalized_url,
            "redirects": []
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Web request failed: {str(e)}",
            "status_code": None,
            "content": "",
            "headers": {},
            "final_url": normalized_url,
            "redirects": []
        }
