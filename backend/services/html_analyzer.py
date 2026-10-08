import re
import urllib.parse
from bs4 import BeautifulSoup
from utils.helpers import safe_fetch_page

SUSPICIOUS_JS_PATTERNS = [
    r'eval\(',
    r'unescape\(',
    r'document\.write\(',
    r'window\.location\s*=',
    r'location\.href\s*=',
    r'onbeforeunload',
    r'event\.preventDefault\(',
    r'contextmenu',
    r'btoa\(',
    r'atob\('
]

def analyze_html(url: str, page_data: dict = None) -> dict:
    """
    Safely inspect webpage HTML structure, form actions, scripts, hidden fields, and links.
    """
    if not page_data:
        page_data = safe_fetch_page(url)

    if not page_data.get("success"):
        return {
            "status": "unavailable",
            "error": page_data.get("error", "Unable to download HTML content."),
            "risk_score": 0,
            "metrics": {},
            "findings": ["Webpage HTML content could not be retrieved for inspection."]
        }

    content = page_data.get("content", "")
    if not content:
        return {
            "status": "unavailable",
            "error": "Empty webpage response content.",
            "risk_score": 0,
            "metrics": {},
            "findings": ["Webpage returned empty HTML body."]
        }

    soup = BeautifulSoup(content, 'html.parser')
    parsed_base = urllib.parse.urlparse(url)
    base_domain = parsed_base.hostname or ""

    # Elements extraction
    forms = soup.find_all('form')
    inputs = soup.find_all('input')
    iframes = soup.find_all('iframe')
    scripts = soup.find_all('script')
    links = soup.find_all('a')
    images = soup.find_all('img')
    meta_tags = soup.find_all('meta')

    # Detailed Input checks
    password_fields = 0
    hidden_fields = 0
    login_fields = 0

    for inp in inputs:
        inp_type = str(inp.get('type', '')).lower()
        inp_name = str(inp.get('name', '')).lower()
        inp_id = str(inp.get('id', '')).lower()
        inp_placeholder = str(inp.get('placeholder', '')).lower()

        if inp_type == 'password':
            password_fields += 1
        elif inp_type == 'hidden':
            hidden_fields += 1

        if any(term in inp_name or term in inp_id or term in inp_placeholder for term in ['login', 'user', 'email', 'pass', 'auth']):
            login_fields += 1

    # Form Actions & Cross-domain Submissions
    external_forms = 0
    empty_forms = 0
    mailto_forms = 0
    suspicious_form_actions = []

    for form in forms:
        action = str(form.get('action', '')).strip()
        if not action or action == '#':
            empty_forms += 1
            suspicious_form_actions.append("Empty or '#' form action target.")
        elif action.startswith('mailto:'):
            mailto_forms += 1
            suspicious_form_actions.append("Form submits sensitive credentials to mailto: address.")
        else:
            parsed_action = urllib.parse.urlparse(urllib.parse.urljoin(url, action))
            action_domain = parsed_action.hostname or ""
            if action_domain and action_domain.lower() != base_domain.lower():
                external_forms += 1
                suspicious_form_actions.append(f"Form submits data cross-domain to: {action_domain}.")

    # Script inspection
    external_scripts = 0
    inline_scripts = 0
    suspicious_js_count = 0

    for script in scripts:
        src = script.get('src')
        if src:
            parsed_src = urllib.parse.urlparse(urllib.parse.urljoin(url, src))
            src_domain = parsed_src.hostname or ""
            if src_domain and src_domain.lower() != base_domain.lower():
                external_scripts += 1
        else:
            inline_scripts += 1
            js_code = script.string or ""
            for pat in SUSPICIOUS_JS_PATTERNS:
                if re.search(pat, js_code, re.IGNORECASE):
                    suspicious_js_count += 1

    # Meta Refresh check
    has_meta_refresh = False
    for meta in meta_tags:
        if str(meta.get('http-equiv', '')).lower() == 'refresh':
            has_meta_refresh = True
            break

    # Hidden element check
    hidden_elements_count = len(soup.find_all(style=re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0', re.I)))

    # Link audit
    external_links = 0
    null_links = 0
    for a in links:
        href = str(a.get('href', '')).strip()
        if not href or href == '#' or href.startswith('javascript:'):
            null_links += 1
        else:
            parsed_href = urllib.parse.urlparse(urllib.parse.urljoin(url, href))
            href_domain = parsed_href.hostname or ""
            if href_domain and href_domain.lower() != base_domain.lower():
                external_links += 1

    total_links = max(1, len(links))
    external_links_ratio = round(external_links / total_links, 2)
    null_links_ratio = round(null_links / total_links, 2)

    # Risk evaluation & Findings
    findings = []
    risk_points = 0

    if password_fields > 0:
        findings.append(f"Login form detected with {password_fields} password field(s).")
        if external_forms > 0:
            findings.append("CRITICAL: Password form submits credentials to external cross-domain server.")
            risk_points += 40
        else:
            risk_points += 10

    if external_forms > 0 and password_fields == 0:
        findings.append(f"Form data submitted to external domain.")
        risk_points += 20

    if mailto_forms > 0:
        findings.append("Form submits data via mailto: action.")
        risk_points += 30

    if empty_forms > 0:
        findings.append(f"{empty_forms} form(s) with empty/dummy action attribute.")
        risk_points += 10

    if len(iframes) > 0:
        findings.append(f"{len(iframes)} iframe element(s) embedded in page.")
        risk_points += 10

    if suspicious_js_count > 0:
        findings.append(f"Suspicious JavaScript functions (obfuscation/eval/redirect) detected.")
        risk_points += 15

    if has_meta_refresh:
        findings.append("Meta refresh tag detected (automatic page redirection).")
        risk_points += 15

    if null_links_ratio > 0.4 and total_links > 5:
        findings.append(f"High percentage of dead/null links ({int(null_links_ratio*100)}%).")
        risk_points += 15

    if hidden_fields > 3:
        findings.append(f"Multiple hidden form inputs ({hidden_fields} fields) present.")
        risk_points += 10

    if risk_points == 0:
        findings.append("HTML structure appears clean with standard form actions and resources.")

    calculated_risk = min(100, risk_points)

    return {
        "status": "analyzed",
        "error": "",
        "risk_score": calculated_risk,
        "metrics": {
            "form_count": len(forms),
            "password_fields": password_fields,
            "login_fields": login_fields,
            "hidden_fields": hidden_fields,
            "iframe_count": len(iframes),
            "script_count": len(scripts),
            "external_scripts": external_scripts,
            "inline_scripts": inline_scripts,
            "suspicious_js_count": suspicious_js_count,
            "external_forms": external_forms,
            "empty_forms": empty_forms,
            "mailto_forms": mailto_forms,
            "has_meta_refresh": has_meta_refresh,
            "total_links": len(links),
            "external_links": external_links,
            "null_links": null_links,
            "external_links_ratio": external_links_ratio,
            "null_links_ratio": null_links_ratio,
            "hidden_elements_count": hidden_elements_count
        },
        "findings": findings
    }
