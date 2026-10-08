import socket
import datetime
import urllib.parse
import whois

def get_domain_age_days(creation_date) -> tuple[int | None, str | None]:
    """Helper to parse creation date and compute age in days. Handles timezone-aware datetimes."""
    if not creation_date:
        return None, None
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if isinstance(creation_date, str):
        try:
            creation_date = datetime.datetime.strptime(creation_date, "%Y-%m-%d")
        except Exception:
            return None, str(creation_date)

    if isinstance(creation_date, datetime.datetime):
        # Strip timezone info to make it naive for safe arithmetic
        creation_naive = creation_date.replace(tzinfo=None)
        today = datetime.datetime.utcnow()
        age = (today - creation_naive).days
        return age, creation_naive.strftime("%Y-%m-%d")

    if isinstance(creation_date, datetime.date):
        today = datetime.date.today()
        age = (today - creation_date).days
        return age, creation_date.strftime("%Y-%m-%d")

    return None, None

def analyze_domain(url: str) -> dict:
    """
    Query domain WHOIS information, age, registrar, and DNS resolution status safely.
    """
    parsed = urllib.parse.urlparse(url if url.startswith(('http://', 'https://')) else f"https://{url}")
    hostname = parsed.hostname or url.split('/')[0]

    # Clean domain from subdomains for WHOIS query (e.g., login.paypal.com -> paypal.com)
    domain_parts = hostname.split('.')
    if len(domain_parts) >= 2:
        root_domain = '.'.join(domain_parts[-2:])
    else:
        root_domain = hostname

    findings = []
    risk_points = 0
    whois_info = None

    try:
        # Perform WHOIS lookup
        whois_info = whois.whois(root_domain)
    except Exception as e:
        # WHOIS lookup failed or blocked by registrar
        pass

    if whois_info and whois_info.get('domain_name'):
        creation_date = whois_info.get('creation_date')
        expiration_date = whois_info.get('expiration_date')
        registrar = whois_info.get('registrar')
        nameservers = whois_info.get('name_servers')

        age_days, creation_str = get_domain_age_days(creation_date)

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        expiration_str = expiration_date.strftime("%Y-%m-%d") if isinstance(expiration_date, (datetime.datetime, datetime.date)) else str(expiration_date or "N/A")

        ns_list = []
        if nameservers:
            if isinstance(nameservers, list):
                ns_list = [str(ns).lower() for ns in nameservers[:3]]
            else:
                ns_list = [str(nameservers).lower()]

        if age_days is not None:
            if age_days < 30:
                findings.append(f"CRITICAL: Domain is very recently registered ({age_days} days old).")
                risk_points += 35
            elif age_days < 180:
                findings.append(f"Domain is relatively new ({age_days} days old).")
                risk_points += 15
            else:
                findings.append(f"Domain is well-established ({age_days} days old, created on {creation_str}).")

        if registrar:
            findings.append(f"Registrar: {registrar}")

        return {
            "status": "analyzed",
            "available": True,
            "error": "",
            "risk_score": min(100, risk_points),
            "metrics": {
                "root_domain": root_domain,
                "domain_age_days": age_days,
                "creation_date": creation_str or "Unavailable",
                "expiration_date": expiration_str or "Unavailable",
                "registrar": str(registrar or "Unavailable"),
                "nameservers": ns_list
            },
            "findings": findings
        }
    else:
        # Fallback when WHOIS is unavailable
        findings.append("Domain registration information unavailable.")
        
        # Test basic DNS resolution
        dns_active = False
        try:
            socket.gethostbyname(hostname)
            dns_active = True
            findings.append("Domain active and successfully resolved via DNS.")
        except Exception:
            findings.append("Domain DNS resolution failed or unreachable.")
            risk_points += 20

        return {
            "status": "unavailable",
            "available": False,
            "error": "Domain registration information unavailable.",
            "risk_score": min(100, risk_points),
            "metrics": {
                "root_domain": root_domain,
                "domain_age_days": None,
                "creation_date": "Unavailable",
                "expiration_date": "Unavailable",
                "registrar": "Unavailable",
                "nameservers": []
            },
            "findings": findings
        }
