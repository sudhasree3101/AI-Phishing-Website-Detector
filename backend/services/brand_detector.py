import re
import urllib.parse
from bs4 import BeautifulSoup

KNOWN_BRANDS = {
    'paypal': {
        'name': 'PayPal',
        'official_domains': ['paypal.com', 'paypal.me', 'paypal-corp.com'],
        'keywords': ['paypal', 'pay-pal', 'paypaI', 'paypol']
    },
    'google': {
        'name': 'Google',
        'official_domains': ['google.com', 'gmail.com', 'youtube.com', 'g.co'],
        'keywords': ['google', 'gmail', 'googe', 'goggl']
    },
    'microsoft': {
        'name': 'Microsoft',
        'official_domains': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'azure.com', 'msn.com'],
        'keywords': ['microsoft', 'outlook', 'office365', 'microsft', 'live-login']
    },
    'apple': {
        'name': 'Apple',
        'official_domains': ['apple.com', 'icloud.com', 'itunes.com'],
        'keywords': ['apple', 'icloud', 'appIe', 'app-store']
    },
    'amazon': {
        'name': 'Amazon',
        'official_domains': ['amazon.com', 'aws.amazon.com', 'media-amazon.com', 'primevideo.com'],
        'keywords': ['amazon', 'primevideo', 'amazn', 'amzn']
    },
    'facebook': {
        'name': 'Meta / Facebook',
        'official_domains': ['facebook.com', 'fb.com', 'meta.com', 'messenger.com'],
        'keywords': ['facebook', 'facebk', 'meta-login', 'fb-security']
    },
    'instagram': {
        'name': 'Instagram',
        'official_domains': ['instagram.com'],
        'keywords': ['instagram', 'instgrm', 'insta-login']
    },
    'netflix': {
        'name': 'Netflix',
        'official_domains': ['netflix.com'],
        'keywords': ['netflix', 'netfIix', 'net-flix']
    },
    'linkedin': {
        'name': 'LinkedIn',
        'official_domains': ['linkedin.com'],
        'keywords': ['linkedin', 'linkdin', 'linked-in']
    },
    'chase': {
        'name': 'Chase Bank',
        'official_domains': ['chase.com'],
        'keywords': ['chase', 'chasebank', 'chase-online']
    },
    'binance': {
        'name': 'Binance',
        'official_domains': ['binance.com'],
        'keywords': ['binance', 'binan-ce', 'binance-auth']
    }
}

def analyze_brand(url: str, page_content: str = "") -> dict:
    """
    Detect potential brand impersonation by cross-referencing URL, domain, page title, and HTML text
    against known official brand domains.
    """
    parsed = urllib.parse.urlparse(url if url.startswith(('http://', 'https://')) else f"https://{url}")
    hostname = (parsed.hostname or "").lower()

    detected_impersonation = []
    official_match = False
    target_brand_name = None
    findings = []
    risk_points = 0

    soup = BeautifulSoup(page_content, 'html.parser') if page_content else None
    page_title = (soup.title.string or "").lower() if soup and soup.title else ""
    page_text = soup.get_text().lower() if soup else ""

    # Check images alt tags for brand logos
    img_alts = " ".join([img.get('alt', '').lower() for img in soup.find_all('img')]) if soup else ""

    combined_text = f"{url.lower()} {page_title} {img_alts}"

    for brand_key, brand_info in KNOWN_BRANDS.items():
        brand_display = brand_info['name']
        official_domains = brand_info['official_domains']
        keywords = brand_info['keywords']

        # Is current hostname an official brand domain?
        is_official = any(hostname == dom or hostname.endswith(f".{dom}") for dom in official_domains)

        if is_official:
            official_match = True
            target_brand_name = brand_display
            findings.append(f"Domain '{hostname}' is confirmed as official domain for {brand_display}.")
            break

        # Check if brand is referenced in URL, title, or logos
        keyword_in_url = any(kw in url.lower() for kw in keywords)
        keyword_in_text = any(kw in page_title or kw in img_alts for kw in keywords)

        if keyword_in_url or keyword_in_text:
            target_brand_name = brand_display
            reason = f"The website contains references to '{brand_display}' but the domain ({hostname}) does not match official brand domains."
            detected_impersonation.append({
                "brand": brand_display,
                "reason": reason,
                "keyword_in_url": keyword_in_url,
                "keyword_in_text": keyword_in_text
            })
            findings.append(f"Possible brand impersonation detected for '{brand_display}'.")
            findings.append(reason)
            risk_points += 35

    if not detected_impersonation and not official_match:
        findings.append("No explicit brand impersonation detected in domain or visible metadata.")

    return {
        "status": "analyzed",
        "is_impersonating": len(detected_impersonation) > 0,
        "official_brand_match": official_match,
        "target_brand": target_brand_name,
        "detected_brands": [d["brand"] for d in detected_impersonation],
        "risk_score": min(100, risk_points),
        "impersonation_details": detected_impersonation,
        "findings": findings
    }
