import re
import math
import urllib.parse
from utils.helpers import normalize_url

SHORTENING_SERVICES = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy', 'tiny.cc', 'shorturl.at', 'clck.ru'
}

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'gq', 'cf', 'tk', 'ml', 'ga', 'racing', 'click',
    'cam', 'zip', 'mov', 'fit', 'rest', 'country', 'buzz', 'icu', 'monster',
    'stream', 'download', 'win', 'vip', 'site', 'online', 'space', 'club'
}

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'auth', 'verify', 'verification', 'account', 'secure',
    'security', 'update', 'banking', 'wallet', 'confirm', 'password', 'credential',
    'support', 'service', 'validation', 'billing', 'recover', 'claim', 'bonus', 'free'
]

COMMON_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'instagram',
    'netflix', 'linkedin', 'chase', 'wellsfargo', 'bankofamerica', 'binance',
    'coinbase', 'stripe', 'meta', 'twitter', 'outlook', 'office365', 'icloud'
]

def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum([p * math.log2(p) for p in prob])

def analyze_url(raw_url: str) -> dict:
    """
    Perform deep structural and semantic URL analysis.
    Returns metrics, extracted features, suspicious indicators, and risk score (0-100).
    """
    url = normalize_url(raw_url)
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Split hostname into domain components
    domain_parts = hostname.split('.')
    tld = domain_parts[-1].lower() if len(domain_parts) > 0 else ""
    
    # Extract subdomains
    subdomain_list = domain_parts[:-2] if len(domain_parts) > 2 else []
    subdomains_count = len(subdomain_list)

    # Basic metrics
    url_length = len(url)
    domain_length = len(hostname)
    dot_count = url.count('.')
    hyphen_count = url.count('-')
    underscore_count = url.count('_')
    at_symbol_count = url.count('@')
    special_char_count = len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|]', url))
    digit_count = sum(c.isdigit() for c in url)
    encoded_char_count = len(re.findall(r'%[0-9a-fA-F]{2}', url))
    query_param_count = len(urllib.parse.parse_qs(query)) if query else 0

    # IP address check
    has_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname))

    # Scheme / HTTPS
    is_https = parsed.scheme.lower() == 'https'

    # Shortening service check
    is_shortened = hostname.lower() in SHORTENING_SERVICES

    # Suspicious TLD check
    is_suspicious_tld = tld in SUSPICIOUS_TLDS

    # Domain Entropy
    domain_entropy = round(calculate_shannon_entropy(hostname), 3)

    # Keyword checks
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    found_brands = [b for b in COMMON_BRANDS if b in url.lower()]

    # Flags & Findings
    findings = []
    risk_points = 0

    if url_length > 75:
        findings.append(f"Unusually long URL length ({url_length} characters).")
        risk_points += 15
    elif url_length > 54:
        findings.append(f"Moderately long URL ({url_length} characters).")
        risk_points += 5

    if dot_count > 4:
        findings.append(f"High dot count in URL ({dot_count} dots).")
        risk_points += 10

    if hyphen_count > 3:
        findings.append(f"Multiple hyphens in domain/URL ({hyphen_count} hyphens).")
        risk_points += 10

    if at_symbol_count > 0:
        findings.append("URL contains '@' symbol, often used to obscure actual host.")
        risk_points += 25

    if has_ip:
        findings.append(f"URL uses direct IP address ({hostname}) instead of registered domain.")
        risk_points += 30

    if is_shortened:
        findings.append("URL uses a known URL shortening service.")
        risk_points += 20

    if is_suspicious_tld:
        findings.append(f"Domain uses high-risk suspicious TLD (.{tld}).")
        risk_points += 20

    if subdomains_count >= 3:
        findings.append(f"Excessive subdomains detected ({subdomains_count} subdomains).")
        risk_points += 15

    if domain_entropy > 4.2:
        findings.append(f"High domain entropy ({domain_entropy}), indicating randomly generated text (DGA).")
        risk_points += 15

    if found_keywords:
        findings.append(f"Suspicious security/login keywords found: {', '.join(found_keywords[:4])}.")
        risk_points += 15

    if not is_https:
        findings.append("URL does not use encrypted HTTPS connection.")
        risk_points += 15
    else:
        findings.append("URL uses HTTPS protocol.")

    if found_brands and not any(hostname.lower() == f"{b}.com" or hostname.lower().endswith(f".{b}.com") for b in found_brands):
        findings.append(f"Target brand keyword ({', '.join(found_brands)}) in non-official domain name.")
        risk_points += 25

    # Calculate normalized risk score (0-100)
    calculated_risk = min(100, risk_points)

    return {
        "metrics": {
            "url_length": url_length,
            "domain_length": domain_length,
            "dot_count": dot_count,
            "hyphen_count": hyphen_count,
            "underscore_count": underscore_count,
            "special_char_count": special_char_count,
            "digit_count": digit_count,
            "query_param_count": query_param_count,
            "subdomains_count": subdomains_count,
            "domain_entropy": domain_entropy,
            "encoded_char_count": encoded_char_count,
            "is_ip": has_ip,
            "is_https": is_https,
            "has_at_symbol": at_symbol_count > 0,
            "is_shortened": is_shortened,
            "is_suspicious_tld": is_suspicious_tld,
            "tld": tld,
            "detected_keywords": found_keywords,
            "detected_brands": found_brands
        },
        "risk_score": calculated_risk,
        "findings": findings
    }
