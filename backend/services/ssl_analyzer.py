import socket
import ssl
import datetime
import urllib.parse

def analyze_ssl(url: str) -> dict:
    """
    Inspect SSL/TLS certificate details, issuer, validity period, and hostname matching.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    is_https = parsed.scheme.lower() == 'https'

    if not is_https:
        return {
            "status": "analyzed",
            "has_ssl": False,
            "error": "Site uses unencrypted HTTP protocol.",
            "risk_score": 30,
            "metrics": {
                "is_https": False,
                "issuer": None,
                "valid_from": None,
                "valid_until": None,
                "days_until_expiration": None,
                "hostname_match": False
            },
            "findings": [
                "Website uses unencrypted HTTP instead of HTTPS.",
                "Data transmitted to this website can be intercepted by third parties."
            ]
        }

    findings = []
    risk_points = 0

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                cert = sslsock.getpeercert()

        # Parse Certificate details
        issuer_dict = dict(x[0] for x in cert.get('issuer', []))
        issuer_name = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or 'Unknown Issuer'

        not_before_str = cert.get('notBefore')
        not_after_str = cert.get('notAfter')

        date_format = r'%b %d %H:%M:%S %Y %Z'
        not_before = datetime.datetime.strptime(not_before_str, date_format) if not_before_str else None
        not_after = datetime.datetime.strptime(not_after_str, date_format) if not_after_str else None

        today = datetime.datetime.utcnow()
        days_until_expiration = (not_after - today).days if not_after else 0
        cert_age_days = (today - not_before).days if not_before else 0

        findings.append(f"Valid HTTPS / SSL certificate issued by {issuer_name}.")
        
        if cert_age_days < 14:
            findings.append(f"SSL certificate was issued very recently ({cert_age_days} days ago).")
            risk_points += 15

        if days_until_expiration < 15:
            findings.append(f"SSL certificate is expiring soon ({days_until_expiration} days remaining).")
            risk_points += 10

        # Important educational note
        findings.append("Note: HTTPS encrypts communication but does not guarantee that a website is legitimate.")

        return {
            "status": "analyzed",
            "has_ssl": True,
            "error": "",
            "risk_score": min(100, risk_points),
            "metrics": {
                "is_https": True,
                "issuer": issuer_name,
                "valid_from": not_before.strftime("%Y-%m-%d") if not_before else "Unknown",
                "valid_until": not_after.strftime("%Y-%m-%d") if not_after else "Unknown",
                "cert_age_days": cert_age_days,
                "days_until_expiration": days_until_expiration,
                "hostname_match": True
            },
            "findings": findings
        }

    except ssl.SSLCertVerificationError as e:
        findings.append(f"SSL Certificate Verification Failed: {e.verify_message}")
        findings.append("Invalid or untrusted SSL certificate detected.")
        findings.append("Note: HTTPS encrypts communication but does not guarantee that a website is legitimate.")
        return {
            "status": "invalid_cert",
            "has_ssl": True,
            "error": str(e),
            "risk_score": 40,
            "metrics": {
                "is_https": True,
                "issuer": "Untrusted / Invalid",
                "hostname_match": False
            },
            "findings": findings
        }
    except Exception as e:
        findings.append(f"Could not establish SSL connection: {str(e)}")
        findings.append("Note: HTTPS encrypts communication but does not guarantee that a website is legitimate.")
        return {
            "status": "unavailable",
            "has_ssl": False,
            "error": f"SSL inspection failed: {str(e)}",
            "risk_score": 20,
            "metrics": {
                "is_https": is_https,
                "issuer": "Unavailable",
                "hostname_match": False
            },
            "findings": findings
        }
