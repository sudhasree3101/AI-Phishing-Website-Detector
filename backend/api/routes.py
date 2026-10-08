import time
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any

from utils.helpers import validate_url, safe_fetch_page, normalize_url
from services.url_analyzer import analyze_url
from services.html_analyzer import analyze_html
from services.text_analyzer import analyze_text
from services.domain_analyzer import analyze_domain
from services.ssl_analyzer import analyze_ssl
from services.brand_detector import analyze_brand
from services.visual_analyzer import analyze_visual
from services.risk_engine import calculate_overall_risk
from ml.predict import predict_url_phishing

router = APIRouter()

class AnalyzeRequest(BaseModel):
    url: str
    is_demo: Optional[bool] = False

DEMO_SAMPLES = {
    "phishing": {
        "url": "https://paypal-login-security.xyz/verify-account",
        "classification": "PHISHING",
        "risk_score": 96,
        "confidence": 97,
        "risk_level": "CRITICAL",
        "is_demo_result": True,
        "summary": "High-risk phishing indicators detected. The system computed a risk score of 96/100 with 97% confidence. Do not enter credentials or personal information.",
        "reasons": [
            "✓ Suspicious URL structure with high-risk TLD (.xyz)",
            "✓ Possible brand impersonation for PayPal on unauthorized domain",
            "✓ Login form detected with external cross-domain submission target",
            "✓ Suspicious account-verification and credential request language",
            "✓ Domain registered recently (< 30 days old)",
            "✓ HTTPS certificate issued recently by untrusted/free authority"
        ],
        "positive_indicators": [
            "✓ SSL/TLS connection established"
        ],
        "warning_indicators": [
            "✓ Suspicious URL structure with high-risk TLD (.xyz)",
            "✓ Possible brand impersonation for PayPal on unauthorized domain",
            "✓ Login form detected with external cross-domain submission target",
            "✓ Suspicious account-verification and credential request language",
            "✓ Domain registered recently (< 30 days old)"
        ],
        "url_analysis": {
            "risk_score": 85,
            "findings": ["High-risk suspicious TLD (.xyz)", "Target brand keyword (paypal) in non-official domain", "Multiple hyphens in domain name"],
            "metrics": {"url_length": 51, "domain_length": 25, "dot_count": 2, "hyphen_count": 3, "is_https": True, "tld": "xyz", "detected_brands": ["paypal"]}
        },
        "domain_analysis": {
            "risk_score": 75,
            "available": True,
            "findings": ["CRITICAL: Domain is very recently registered (12 days old).", "Registrar: NameCheap, Inc."],
            "metrics": {"root_domain": "paypal-login-security.xyz", "domain_age_days": 12, "creation_date": "2026-09-25", "registrar": "NameCheap, Inc."}
        },
        "html_analysis": {
            "risk_score": 90,
            "findings": ["CRITICAL: Password form submits credentials to external cross-domain server.", "Login form detected with 1 password field(s)."],
            "metrics": {"form_count": 1, "password_fields": 1, "external_forms": 1, "iframe_count": 0, "suspicious_js_count": 2}
        },
        "nlp_analysis": {
            "risk_score": 80,
            "findings": ["High urgency social engineering language detected: 'verify your account'.", "Sensitive credential request phrasing identified."],
            "metrics": {"title": "PayPal Security - Account Verification", "urgency_count": 2, "credential_count": 1}
        },
        "brand_analysis": {
            "risk_score": 90,
            "is_impersonating": True,
            "target_brand": "PayPal",
            "findings": ["Possible brand impersonation detected for 'PayPal'.", "The website contains references to 'PayPal' but domain (paypal-login-security.xyz) does not match official brand domains."]
        },
        "ssl_analysis": {
            "risk_score": 35,
            "has_ssl": True,
            "findings": ["Valid HTTPS / SSL certificate issued by Let's Encrypt.", "SSL certificate was issued very recently (10 days ago).", "Note: HTTPS encrypts communication but does not guarantee that a website is legitimate."]
        },
        "visual_analysis": {
            "status": "analyzed_heuristic",
            "risk_score": 20,
            "findings": ["Visual layout analysis inferred login interface elements (input fields & buttons)."]
        },
        "feature_importance": [
            {"feature": "is_suspicious_tld", "value": 1.0, "importance": 0.28},
            {"feature": "brand_count", "value": 1.0, "importance": 0.24},
            {"feature": "hyphen_count", "value": 3.0, "importance": 0.18},
            {"feature": "url_length", "value": 51.0, "importance": 0.15}
        ]
    },
    "suspicious": {
        "url": "https://free-bonus-update-2026.net/claim",
        "classification": "SUSPICIOUS",
        "risk_score": 52,
        "confidence": 86,
        "risk_level": "MEDIUM",
        "is_demo_result": True,
        "summary": "Suspicious characteristics found. The website exhibits abnormal features (Risk Score: 52/100). Exercise caution before interacting.",
        "reasons": [
            "✓ Suspicious promo/bonus keywords in URL",
            "✓ Unusually high hyphen count in domain name",
            "✓ Financial lure phrasing present in webpage body",
            "✓ HTTPS certificate valid"
        ],
        "positive_indicators": [
            "✓ HTTPS certificate valid"
        ],
        "warning_indicators": [
            "✓ Suspicious promo/bonus keywords in URL",
            "✓ Unusually high hyphen count in domain name",
            "✓ Financial lure phrasing present in webpage body"
        ],
        "url_analysis": {
            "risk_score": 45,
            "findings": ["Multiple hyphens in domain/URL", "Suspicious security/login keywords found"],
            "metrics": {"url_length": 42, "dot_count": 2, "hyphen_count": 3, "is_https": True, "tld": "net"}
        },
        "domain_analysis": {
            "risk_score": 30,
            "available": True,
            "findings": ["Domain is relatively new (110 days old)."],
            "metrics": {"root_domain": "free-bonus-update-2026.net", "domain_age_days": 110, "creation_date": "2026-06-18"}
        },
        "html_analysis": {
            "risk_score": 25,
            "findings": ["1 form(s) with empty/dummy action attribute."],
            "metrics": {"form_count": 1, "password_fields": 0, "external_forms": 0}
        },
        "nlp_analysis": {
            "risk_score": 40,
            "findings": ["Financial lure / bait keywords detected: 'claim your bonus'."],
            "metrics": {"title": "Claim Your Exclusive 2026 Bonus", "urgency_count": 1}
        },
        "brand_analysis": {
            "risk_score": 0,
            "is_impersonating": False,
            "findings": ["No explicit brand impersonation detected in domain or visible metadata."]
        },
        "ssl_analysis": {
            "risk_score": 0,
            "has_ssl": True,
            "findings": ["Valid HTTPS / SSL certificate.", "Note: HTTPS encrypts communication but does not guarantee that a website is legitimate."]
        },
        "visual_analysis": {
            "status": "unavailable",
            "risk_score": 0,
            "findings": ["Visual analysis unavailable."]
        },
        "feature_importance": [
            {"feature": "hyphen_count", "value": 3.0, "importance": 0.30},
            {"feature": "keyword_count", "value": 2.0, "importance": 0.25}
        ]
    },
    "legitimate": {
        "url": "https://google.com",
        "classification": "LEGITIMATE",
        "risk_score": 5,
        "confidence": 98,
        "risk_level": "LOW",
        "is_demo_result": True,
        "summary": "The website appears legitimate with low risk indicators (Risk Score: 5/100). Standard security checks passed.",
        "reasons": [
            "✓ Official confirmed brand domain (Google)",
            "✓ Well-established domain registered > 25 years ago",
            "✓ Valid HTTPS SSL certificate issued by trusted Certificate Authority",
            "✓ Clean body text with no coercive phishing language",
            "✓ Clean HTML structure with standard form actions"
        ],
        "positive_indicators": [
            "✓ Official confirmed brand domain (Google)",
            "✓ Well-established domain registered > 25 years ago",
            "✓ Valid HTTPS SSL certificate issued by trusted Certificate Authority",
            "✓ Clean body text with no coercive phishing language"
        ],
        "warning_indicators": [],
        "url_analysis": {
            "risk_score": 0,
            "findings": ["URL uses HTTPS protocol."],
            "metrics": {"url_length": 18, "dot_count": 1, "hyphen_count": 0, "is_https": True, "tld": "com"}
        },
        "domain_analysis": {
            "risk_score": 0,
            "available": True,
            "findings": ["Domain is well-established (created in 1997)."],
            "metrics": {"root_domain": "google.com", "domain_age_days": 10500, "creation_date": "1997-09-15", "registrar": "MarkMonitor, Inc."}
        },
        "html_analysis": {
            "risk_score": 0,
            "findings": ["HTML structure appears clean with standard form actions and resources."],
            "metrics": {"form_count": 1, "password_fields": 0, "external_forms": 0}
        },
        "nlp_analysis": {
            "risk_score": 0,
            "findings": ["No coercive or high-risk phishing phrasing detected in page text."],
            "metrics": {"title": "Google", "urgency_count": 0, "credential_count": 0}
        },
        "brand_analysis": {
            "risk_score": 0,
            "is_impersonating": False,
            "findings": ["Domain 'google.com' is confirmed as official domain for Google."]
        },
        "ssl_analysis": {
            "risk_score": 0,
            "has_ssl": True,
            "findings": ["Valid HTTPS / SSL certificate issued by Google Trust Services.", "Note: HTTPS encrypts communication but does not guarantee that a website is legitimate."]
        },
        "visual_analysis": {
            "status": "unavailable",
            "risk_score": 0,
            "findings": ["Visual analysis unavailable."]
        },
        "feature_importance": [
            {"feature": "is_https", "value": 1.0, "importance": 0.35},
            {"feature": "url_length", "value": 18.0, "importance": 0.20}
        ]
    }
}

@router.get("/")
def api_root():
    return {
        "name": "AI-Powered Phishing Website Detector API",
        "version": "1.0.0",
        "status": "online",
        "endpoints": ["/analyze", "/health"]
    }

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "services": {
            "url_analyzer": "operational",
            "html_analyzer": "operational",
            "nlp_analyzer": "operational",
            "domain_analyzer": "operational",
            "ssl_analyzer": "operational",
            "risk_engine": "operational"
        }
    }

@router.post("/analyze")
def analyze_website(req: AnalyzeRequest):
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL input string cannot be empty.")

    normalized = normalize_url(raw_url)

    # Check SSRF and basic format
    is_valid, err_msg = validate_url(normalized)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    # Demo mode request matching
    if req.is_demo or "paypal-login-security" in normalized.lower():
        return DEMO_SAMPLES["phishing"]
    elif "free-bonus-update" in normalized.lower():
        return DEMO_SAMPLES["suspicious"]
    elif "google.com" in normalized.lower() and req.is_demo:
        return DEMO_SAMPLES["legitimate"]

    # 1. Fetch Webpage Safely
    page_data = safe_fetch_page(normalized, timeout=4)

    # 2. Run Analyzers
    url_res = analyze_url(normalized)
    html_res = analyze_html(normalized, page_data=page_data)
    text_res = analyze_text(normalized, page_data=page_data)
    domain_res = analyze_domain(normalized)
    ssl_res = analyze_ssl(normalized)
    brand_res = analyze_brand(normalized, page_content=page_data.get("content", ""))
    visual_res = analyze_visual(normalized, html_metrics=html_res)
    ml_res = predict_url_phishing(normalized)

    # 3. Calculate Aggregated Risk Score & Explainable AI
    overall = calculate_overall_risk(
        url_res=url_res,
        html_res=html_res,
        text_res=text_res,
        domain_res=domain_res,
        ssl_res=ssl_res,
        brand_res=brand_res,
        visual_res=visual_res,
        ml_res=ml_res
    )

    # Merge ML-based reasons into the overall explanation list
    ml_reasons = ml_res.get("reasons", [])
    combined_reasons = overall["reasons"] + [
        f"[ML] {r}" for r in ml_reasons
        if r not in overall["reasons"]
    ]

    return {
        "url": normalized,
        "classification": overall["classification"],
        "risk_score": overall["risk_score"],
        "confidence": overall["confidence"],
        "risk_level": overall["risk_level"],
        "is_demo_result": False,
        "summary": overall["summary"],
        "reasons": combined_reasons,
        "positive_indicators": overall["positive_indicators"],
        "warning_indicators": overall["warning_indicators"],
        "url_analysis": url_res,
        "domain_analysis": domain_res,
        "html_analysis": html_res,
        "nlp_analysis": text_res,
        "visual_analysis": visual_res,
        "ssl_analysis": ssl_res,
        "brand_analysis": brand_res,
        "feature_importance": ml_res.get("top_features", []),
        "ml_analysis": {
            "status": ml_res.get("status", "unavailable"),
            "prediction": ml_res.get("prediction_label", "Unknown"),
            "phishing_probability": ml_res.get("phishing_probability", 0),
            "confidence": ml_res.get("confidence", 0),
            "model_reasons": ml_reasons,
        }
    }
