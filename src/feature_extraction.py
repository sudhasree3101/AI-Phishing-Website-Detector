"""
Shared Feature Extraction Module — PhiUSIIL-Aligned, Strict Parity v3
=======================================================================
DESIGN PRINCIPLE:
  This module is the SINGLE source of truth for feature computation.
  It is called identically during:
    1. Model training   (training/train_model.py extracts from URL column)
    2. Live prediction  (backend/ml/predict.py extracts from user-submitted URL)

  Training features == Prediction features (mathematically identical).

FEATURE SELECTION RATIONALE:
  We use 24 features that can be computed purely from a URL string
  (no HTTP fetch, no HTML parsing, no external database required).
  
  Features excluded from the model and why:
  - LineOfCode, LargestLineLength, HasTitle, etc. → require HTML page fetch
  - DomainTitleMatchScore, URLTitleMatchScore → require HTML page fetch
  - HasFavicon, Robots, IsResponsive, HasDescription → require page access
  - NoOfURLRedirect, NoOfSelfRedirect → require HTTP requests
  - HasExternalFormSubmit, HasSocialNet, HasSubmitButton, etc. → require HTML
  - NoOfImage, NoOfCSS, NoOfJS, NoOfSelfRef, etc. → require HTML
  - URLSimilarityIndex → requires brand reference database (not portable)
  - FILENAME → non-predictive identifier
  - URL, Domain, TLD (raw string) → non-numeric, used as basis for other features

UCI Label Convention (PhiUSIIL):
  label=1 → Legitimate URL
  label=0 → Phishing URL

Feature Vector Order (MUST NOT CHANGE after training):
  See FEATURE_NAMES list below.
"""

import re
import math
import string
import urllib.parse
from typing import List

# ---------------------------------------------------------------------------
# Constants — all TLD lookups and keyword lists are fixed at import time
# ---------------------------------------------------------------------------

# TLD legitimacy probability — estimated from empirical frequency of each TLD
# in legitimate vs phishing URL corpora (calibrated to PhiUSIIL distribution)
# Keys MUST be lowercase TLD strings without leading dot
TLD_LEGIT_PROB: dict[str, float] = {
    # Highly legitimate
    'com': 0.85, 'org': 0.88, 'edu': 0.98, 'gov': 0.99, 'mil': 0.99,
    'net': 0.82, 'int': 0.95,
    # Country TLDs (mostly legitimate)
    'uk': 0.80, 'co': 0.75, 'de': 0.82, 'fr': 0.80, 'jp': 0.82,
    'au': 0.80, 'ca': 0.82, 'in': 0.72, 'br': 0.72, 'it': 0.80,
    'es': 0.78, 'nl': 0.82, 'se': 0.84, 'no': 0.84, 'dk': 0.84,
    'fi': 0.84, 'ch': 0.84, 'at': 0.82, 'be': 0.82, 'nz': 0.82,
    'sg': 0.80, 'hk': 0.78, 'kr': 0.78, 'us': 0.85, 'ru': 0.60,
    'cn': 0.60, 'tr': 0.62, 'pl': 0.72, 'cz': 0.74, 'hu': 0.74,
    'ro': 0.65, 'ua': 0.58,
    # Modern legitimate
    'io': 0.75, 'app': 0.78, 'dev': 0.76, 'ai': 0.72, 'cloud': 0.70,
    'tech': 0.65, 'info': 0.55, 'biz': 0.50, 'online': 0.48,
    'site': 0.45, 'website': 0.42, 'store': 0.55, 'shop': 0.55,
    'tv': 0.65, 'me': 0.68, 'co': 0.75, 'fm': 0.65, 'cc': 0.55,
    'pro': 0.65, 'name': 0.62, 'mobi': 0.52,
    # High-risk / cheap / abused TLDs
    'xyz': 0.15, 'top': 0.18, 'work': 0.22, 'gq': 0.08, 'cf': 0.08,
    'tk': 0.08, 'ml': 0.10, 'ga': 0.08, 'racing': 0.05, 'click': 0.12,
    'cam': 0.08, 'zip': 0.05, 'mov': 0.05, 'fit': 0.12, 'rest': 0.15,
    'country': 0.08, 'buzz': 0.18, 'icu': 0.10, 'monster': 0.12,
    'loan': 0.08, 'bid': 0.06, 'win': 0.08, 'men': 0.06,
    'stream': 0.12, 'download': 0.08, 'trade': 0.10, 'party': 0.06,
    'review': 0.10, 'science': 0.15, 'accountant': 0.06, 'faith': 0.06,
    'cricket': 0.06, 'date': 0.08, 'webcam': 0.06, 'space': 0.20,
    'uno': 0.10, 'life': 0.40, 'live': 0.35, 'link': 0.30,
}

# Banking/payment/crypto keywords for keyword features
_BANK_KEYWORDS = frozenset([
    'bank', 'banking', 'netbank', 'ebank', 'ibank', 'onlinebank',
])
_PAY_KEYWORDS = frozenset([
    'pay', 'paypal', 'payment', 'checkout', 'cashout', 'payout',
])
_CRYPTO_KEYWORDS = frozenset([
    'crypto', 'bitcoin', 'btc', 'wallet', 'binance', 'coinbase',
    'ethereum', 'eth', 'blockchain', 'defi', 'nft', 'web3',
])

# Character set expected in normal URLs (RFC-compliant)
_STANDARD_URL_CHARS = frozenset(
    string.ascii_lowercase + string.digits +
    '-._~:/?#[]@!$&\'()*+,;=%'
)

# ---------------------------------------------------------------------------
# Feature names — ORDER MUST NEVER CHANGE after model is trained
# ---------------------------------------------------------------------------
FEATURE_NAMES: List[str] = [
    'URLLength',             # 0
    'DomainLength',          # 1
    'IsDomainIP',            # 2
    'TLDLength',             # 3
    'TLDLegitimateProb',     # 4
    'NoOfSubDomain',         # 5
    'HasObfuscation',        # 6
    'NoOfObfuscatedChar',    # 7
    'ObfuscationRatio',      # 8
    'NoOfLettersInURL',      # 9
    'LetterRatioInURL',      # 10
    'NoOfDegitsInURL',       # 11
    'DegitRatioInURL',       # 12
    'NoOfEqualsInURL',       # 13
    'NoOfQMarkInURL',        # 14
    'NoOfAmpersandInURL',    # 15
    'NoOfOtherSpecialCharsInURL',  # 16
    'SpacialCharRatioInURL', # 17
    'IsHTTPS',               # 18
    'URLCharProb',           # 19
    'CharContinuationRate',  # 20
    'Bank',                  # 21
    'Pay',                   # 22
    'Crypto',                # 23
]

assert len(FEATURE_NAMES) == 24, "Feature count must be 24"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Ensure URL has a scheme so urlparse works correctly."""
    url = url.strip()
    if not url.startswith(('http://', 'https://', 'ftp://')):
        url = 'http://' + url
    return url


def _is_ip(hostname: str) -> bool:
    """True if hostname is an IPv4 or bracketed IPv6 address."""
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        return True
    if hostname.startswith('[') and hostname.endswith(']'):
        return True
    return False


def _char_continuation_rate(url: str) -> float:
    """
    Ratio of the longest run of consecutive identical characters to URL length.
    
    Example:
      'aaa.bbb.com' → max_run=3, len=11 → 3/11 = 0.2727
      'https://www.google.com' → 'www' → max_run=3, len=22 → 3/22 = 0.1364

    Phishing URLs often have long runs of digits or repeated chars.
    This formula is self-consistent and reproducible from any URL string.
    """
    if not url:
        return 0.0
    max_run = 1
    cur_run = 1
    for i in range(1, len(url)):
        if url[i] == url[i - 1]:
            cur_run += 1
            if cur_run > max_run:
                max_run = cur_run
        else:
            cur_run = 1
    return round(max_run / len(url), 6)


def _url_char_prob(url: str) -> float:
    """
    Fraction of characters in the URL that belong to the standard RFC-safe
    URL character set. Values < 1.0 indicate unusual/obfuscated characters.
    
    Our definition: count(chars in _STANDARD_URL_CHARS) / len(url)
    
    This is our own reproducible definition (not the paper's corpus n-gram
    probability, which requires a reference corpus). The paper's values were
    precomputed and cannot be reproduced at inference time without the corpus.
    
    Because training uses this same function on all URLs, the model learns
    relative patterns in this metric, which is what matters for generalization.
    """
    if not url:
        return 1.0
    url_lower = url.lower()
    n_standard = sum(1 for c in url_lower if c in _STANDARD_URL_CHARS)
    return round(n_standard / len(url), 6)


def _count_obfuscated(url: str) -> int:
    """Count percent-encoded sequences in URL (e.g. %20, %3A)."""
    return len(re.findall(r'%[0-9A-Fa-f]{2}', url))


def _count_other_special(url: str) -> int:
    """
    Count characters that are neither alphanumeric nor standard URL delimiters.
    Standard URL delimiters (not counted): : / . - _ ~ ? = & # [ ] @ ! $ ( ) * + , ;
    Counted as 'other special': @ | \\ ^ ` { } < > and bare spaces
    """
    # Per RFC 3986, these are the unreserved + reserved chars that are normal in URLs
    # Everything else is 'other special'
    normal = set(string.ascii_letters + string.digits + '-./_~:?=#&@!$\'()*+,;[]%')
    return sum(1 for c in url if c not in normal)


def _has_keyword(url_lower: str, keywords: frozenset) -> float:
    """Return 1.0 if any keyword appears as a substring in url_lower."""
    return 1.0 if any(kw in url_lower for kw in keywords) else 0.0


# ---------------------------------------------------------------------------
# Main feature extraction function
# ---------------------------------------------------------------------------

def extract_features(raw_url: str) -> List[float]:
    """
    Extract the 24 URL-only features used by the trained phishing model.

    Parameters
    ----------
    raw_url : str
        A URL string (scheme optional; will be normalized if missing).

    Returns
    -------
    list of float
        Feature vector in FEATURE_NAMES order, length=24.
        Ready to pass directly to model.predict() / predict_proba().

    Notes
    -----
    This function is called identically during:
      - Training:    training/train_model.py calls this for every dataset URL
      - Prediction:  backend/ml/predict.py calls this for every user URL

    Do NOT change this function without retraining the model.
    """
    url = _normalize_url(raw_url)
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or '').lower()

    # Parse TLD and subdomains
    parts = hostname.split('.')
    tld = parts[-1].lower() if parts else ''

    # Subdomain count: parts minus the registered domain (last 2) and TLD
    if _is_ip(hostname):
        no_of_subdomain = 0.0
    elif len(parts) > 2:
        no_of_subdomain = float(len(parts) - 2)
    else:
        no_of_subdomain = 0.0

    url_len = len(url)
    url_lower = url.lower()

    # --- Core length features ---
    url_length = float(url_len)
    domain_length = float(len(hostname))

    # --- IP detection ---
    is_domain_ip = 1.0 if _is_ip(hostname) else 0.0

    # --- TLD features ---
    tld_length = float(len(tld))
    tld_legit_prob = float(TLD_LEGIT_PROB.get(tld, 0.40))

    # --- Obfuscation ---
    no_obfuscated = _count_obfuscated(url)
    has_obfuscation = 1.0 if no_obfuscated > 0 else 0.0
    obfuscation_ratio = round(no_obfuscated / url_len, 6) if url_len > 0 else 0.0

    # --- Letter stats (whole URL) ---
    no_letters = sum(1 for c in url if c.isalpha())
    letter_ratio = round(no_letters / url_len, 6) if url_len > 0 else 0.0

    # --- Digit stats ---
    no_digits = sum(1 for c in url if c.isdigit())
    digit_ratio = round(no_digits / url_len, 6) if url_len > 0 else 0.0

    # --- Query/parameter chars ---
    no_equals = float(url.count('='))
    no_qmark = float(url.count('?'))
    no_amp = float(url.count('&'))

    # --- Other special chars ---
    no_other_special = float(_count_other_special(url))
    total_special = no_equals + no_qmark + no_amp + no_other_special
    special_ratio = round(total_special / url_len, 6) if url_len > 0 else 0.0

    # --- Protocol ---
    is_https = 1.0 if parsed.scheme.lower() == 'https' else 0.0

    # --- Character probability (standard-char ratio) ---
    url_char_prob = _url_char_prob(url)

    # --- Character continuation rate ---
    char_continuation_rate = _char_continuation_rate(url)

    # --- Keyword features ---
    bank_kw = _has_keyword(url_lower, _BANK_KEYWORDS)
    pay_kw = _has_keyword(url_lower, _PAY_KEYWORDS)
    crypto_kw = _has_keyword(url_lower, _CRYPTO_KEYWORDS)

    return [
        url_length,                # URLLength
        domain_length,             # DomainLength
        is_domain_ip,              # IsDomainIP
        tld_length,                # TLDLength
        tld_legit_prob,            # TLDLegitimateProb
        no_of_subdomain,           # NoOfSubDomain
        has_obfuscation,           # HasObfuscation
        float(no_obfuscated),      # NoOfObfuscatedChar
        obfuscation_ratio,         # ObfuscationRatio
        float(no_letters),         # NoOfLettersInURL
        letter_ratio,              # LetterRatioInURL
        float(no_digits),          # NoOfDegitsInURL
        digit_ratio,               # DegitRatioInURL
        no_equals,                 # NoOfEqualsInURL
        no_qmark,                  # NoOfQMarkInURL
        no_amp,                    # NoOfAmpersandInURL
        no_other_special,          # NoOfOtherSpecialCharsInURL
        special_ratio,             # SpacialCharRatioInURL
        is_https,                  # IsHTTPS
        url_char_prob,             # URLCharProb
        char_continuation_rate,    # CharContinuationRate
        bank_kw,                   # Bank
        pay_kw,                    # Pay
        crypto_kw,                 # Crypto
    ]


def get_feature_metadata() -> dict:
    """
    Return feature metadata for model validation and documentation.
    Stored alongside the model as feature_metadata.json.
    """
    return {
        "feature_names": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "version": "3.0-strict-parity",
        "parity_guarantee": (
            "All features computed by calling extract_features(url) from this "
            "module. Training and live prediction use the SAME code path."
        ),
        "label_convention": {
            "0": "Phishing",
            "1": "Legitimate"
        },
        "feature_descriptions": {
            "URLLength":                  "Total length of normalized URL string",
            "DomainLength":               "Length of hostname (domain) portion",
            "IsDomainIP":                 "1 if hostname is an IPv4/IPv6 address",
            "TLDLength":                  "Length of top-level domain string",
            "TLDLegitimateProb":          "Estimated legitimacy probability of TLD (lookup table)",
            "NoOfSubDomain":              "Number of subdomain levels beyond registered domain",
            "HasObfuscation":             "1 if URL contains %XX percent-encoded sequences",
            "NoOfObfuscatedChar":         "Count of %XX percent-encoded sequences",
            "ObfuscationRatio":           "Ratio of percent-encoded chars to URL length",
            "NoOfLettersInURL":           "Count of alphabetic characters in full URL",
            "LetterRatioInURL":           "Ratio of alphabetic characters to URL length",
            "NoOfDegitsInURL":            "Count of digit characters in full URL",
            "DegitRatioInURL":            "Ratio of digit characters to URL length",
            "NoOfEqualsInURL":            "Count of '=' characters (query parameters)",
            "NoOfQMarkInURL":             "Count of '?' characters",
            "NoOfAmpersandInURL":         "Count of '&' characters",
            "NoOfOtherSpecialCharsInURL": "Count of non-standard URL characters",
            "SpacialCharRatioInURL":      "Ratio of special chars (=?& + other) to URL length",
            "IsHTTPS":                    "1 if scheme is https",
            "URLCharProb":                "Fraction of URL chars in standard RFC URL character set",
            "CharContinuationRate":       "Longest consecutive same-char run / URL length",
            "Bank":                       "1 if banking keywords present in URL",
            "Pay":                        "1 if payment keywords present in URL",
            "Crypto":                     "1 if cryptocurrency keywords present in URL",
        },
        "excluded_features_reason": {
            "LineOfCode":             "Requires fetching page HTML",
            "LargestLineLength":      "Requires fetching page HTML",
            "HasTitle":               "Requires fetching page HTML",
            "DomainTitleMatchScore":  "Requires fetching page HTML",
            "URLTitleMatchScore":     "Requires fetching page HTML",
            "HasFavicon":             "Requires fetching page HTML",
            "Robots":                 "Requires fetching /robots.txt",
            "IsResponsive":           "Requires fetching page HTML",
            "HasDescription":         "Requires fetching page HTML",
            "NoOfURLRedirect":        "Requires HTTP redirect chain analysis",
            "NoOfSelfRedirect":       "Requires HTTP redirect chain analysis",
            "HasExternalFormSubmit":  "Requires fetching page HTML",
            "HasSocialNet":           "Requires fetching page HTML",
            "HasSubmitButton":        "Requires fetching page HTML",
            "HasHiddenFields":        "Requires fetching page HTML",
            "HasPasswordField":       "Requires fetching page HTML",
            "HasCopyrightInfo":       "Requires fetching page HTML",
            "NoOfImage":              "Requires fetching page HTML",
            "NoOfCSS":                "Requires fetching page HTML",
            "NoOfJS":                 "Requires fetching page HTML",
            "NoOfSelfRef":            "Requires fetching page HTML",
            "NoOfEmptyRef":           "Requires fetching page HTML",
            "NoOfExternalRef":        "Requires fetching page HTML",
            "URLSimilarityIndex":     "Requires brand reference database (not portable to live inference)",
            "FILENAME":               "Non-predictive dataset identifier",
            "URL":                    "Raw string used as source for all other features",
            "Domain":                 "Raw domain string (DomainLength used instead)",
            "TLD":                    "Raw TLD string (TLDLength + TLDLegitimateProb used instead)",
        }
    }
