import re
from bs4 import BeautifulSoup
from utils.helpers import safe_fetch_page

URGENCY_KEYWORDS = [
    r'verify your account',
    r'account (will be|has been) (suspended|locked|terminated|disabled)',
    r'immediate action required',
    r'confirm your (password|identity|credentials|email)',
    r'unusual activity detected',
    r'security (alert|warning|notice)',
    r'within 24 hours',
    r'urgent update needed',
    r'avoid account closure',
    r'failure to verify',
    r'unauthorized login attempt'
]

CREDENTIAL_KEYWORDS = [
    r'enter your (password|passcode|pin|ssn)',
    r'social security number',
    r'credit card (number|details|info)',
    r'cvv|cvc',
    r'billing details',
    r'security question',
    r'two-factor authentication code',
    r'secret key|seed phrase|private key'
]

FINANCIAL_KEYWORDS = [
    r'payment failure',
    r'refund processed',
    r'invoice overdue',
    r'tax refund',
    r'claim your (reward|bonus|prize|\$|USD|crypto)',
    r'transaction failed',
    r'verify billing'
]

def analyze_text(url: str, page_data: dict = None) -> dict:
    """
    Perform NLP and social engineering text analysis on webpage title, headings, and visible body text.
    """
    if not page_data:
        page_data = safe_fetch_page(url)

    if not page_data.get("success") or not page_data.get("content"):
        return {
            "status": "unavailable",
            "error": page_data.get("error", "Webpage text unavailable."),
            "risk_score": 0,
            "metrics": {
                "title": "",
                "headings": [],
                "urgency_matches": [],
                "credential_matches": [],
                "financial_matches": []
            },
            "findings": ["Text analysis could not be performed because webpage content was unreachable."]
        }

    soup = BeautifulSoup(page_data["content"], 'html.parser')

    # Extract title
    title = soup.title.string.strip() if soup.title and soup.title.string else ""

    # Extract headings
    headings = []
    for tag in ['h1', 'h2', 'h3']:
        for h in soup.find_all(tag):
            txt = h.get_text(strip=True)
            if txt and len(txt) < 150:
                headings.append(txt)

    # Extract visible body text (excluding scripts, styles)
    for element in soup(["script", "style", "meta", "noscript"]):
        element.extract()
    body_text = soup.get_text(separator=' ', strip=True).lower()

    # Search for patterns
    urgency_found = []
    for pat in URGENCY_KEYWORDS:
        matches = re.findall(pat, body_text, re.IGNORECASE)
        if matches:
            urgency_found.append(pat.replace(r'\s*', ' ').replace(r'|', '/'))

    credential_found = []
    for pat in CREDENTIAL_KEYWORDS:
        matches = re.findall(pat, body_text, re.IGNORECASE)
        if matches:
            credential_found.append(pat.replace(r'\s*', ' ').replace(r'|', '/'))

    financial_found = []
    for pat in FINANCIAL_KEYWORDS:
        matches = re.findall(pat, body_text, re.IGNORECASE)
        if matches:
            financial_found.append(pat.replace(r'\s*', ' ').replace(r'|', '/'))

    # Calculate NLP risk points
    findings = []
    risk_points = 0

    if urgency_found:
        findings.append(f"High urgency social engineering language detected: '{urgency_found[0]}'.")
        risk_points += 30

    if credential_found:
        findings.append(f"Sensitive credential request phrasing identified: '{credential_found[0]}'.")
        risk_points += 35

    if financial_found:
        findings.append(f"Financial lure / bait keywords detected: '{financial_found[0]}'.")
        risk_points += 20

    if not title:
        findings.append("Webpage has an empty or missing HTML <title> tag.")
        risk_points += 10

    if risk_points == 0:
        findings.append("No coercive or high-risk phishing phrasing detected in page text.")

    calculated_risk = min(100, risk_points)

    return {
        "status": "analyzed",
        "error": "",
        "risk_score": calculated_risk,
        "metrics": {
            "title": title,
            "headings_count": len(headings),
            "sample_headings": headings[:3],
            "text_length": len(body_text),
            "urgency_count": len(urgency_found),
            "credential_count": len(credential_found),
            "financial_count": len(financial_found),
            "urgency_matches": urgency_found,
            "credential_matches": credential_found,
            "financial_matches": financial_found
        },
        "findings": findings
    }
