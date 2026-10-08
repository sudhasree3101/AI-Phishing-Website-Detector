def calculate_overall_risk(
    url_res: dict,
    html_res: dict,
    text_res: dict,
    domain_res: dict,
    ssl_res: dict,
    brand_res: dict,
    visual_res: dict,
    ml_res: dict,
    weights: dict = None
) -> dict:
    """
    Synthesize all analyzer signals into a single multi-perspective risk score (0-100),
    determine security status level, confidence score, and generate Explainable AI findings.
    """
    if weights is None:
        weights = {
            "url": 0.25,
            "html": 0.20,
            "domain": 0.15,
            "nlp": 0.15,
            "brand": 0.15,
            "ssl": 0.10
        }

    score_url = url_res.get("risk_score", 0)
    score_html = html_res.get("risk_score", 0)
    score_nlp = text_res.get("risk_score", 0)
    score_domain = domain_res.get("risk_score", 0)
    score_ssl = ssl_res.get("risk_score", 0)
    score_brand = brand_res.get("risk_score", 0)
    score_ml = ml_res.get("phishing_probability", 0)

    # Weighted composite score calculation
    composite_score = (
        score_url * weights["url"] +
        score_html * weights["html"] +
        score_domain * weights["domain"] +
        score_nlp * weights["nlp"] +
        score_brand * weights["brand"] +
        score_ssl * weights["ssl"]
    )

    # Blend with ML model probability if available
    if ml_res.get("status") == "model_prediction":
        composite_score = composite_score * 0.7 + score_ml * 0.3

    final_risk_score = int(round(max(0, min(100, composite_score))))

    # Risk level categorization
    if final_risk_score >= 80:
        risk_level = "CRITICAL"
        classification = "PHISHING"
    elif final_risk_score >= 60:
        risk_level = "HIGH"
        classification = "PHISHING"
    elif final_risk_score >= 30:
        risk_level = "MEDIUM"
        classification = "SUSPICIOUS"
    else:
        risk_level = "LOW"
        classification = "LEGITIMATE"

    # Signal alignment confidence calculation
    signal_scores = [score_url, score_html, score_nlp, score_domain, score_brand]
    high_count = sum(1 for s in signal_scores if s >= 40)
    low_count = sum(1 for s in signal_scores if s < 25)

    if high_count >= 3 or low_count >= 4:
        confidence = min(98, 85 + max(high_count, low_count) * 3)
    else:
        confidence = 82

    # Explainable AI - Reason extraction
    reasons = []
    positive_indicators = []
    warning_indicators = []

    # 1. URL Analysis
    for find in url_res.get("findings", []):
        if "uses HTTPS" in find:
            positive_indicators.append("✓ Secure HTTPS protocol detected in URL")
        elif "Unusually long" in find or "Multiple hyphens" in find or "High dot count" in find:
            warning_indicators.append(f"✓ {find}")
        elif "@" in find or "direct IP address" in find or "shortening service" in find or "suspicious TLD" in find:
            warning_indicators.append(f"✓ {find}")

    # 2. HTML Analysis
    for find in html_res.get("findings", []):
        if "Password form submits credentials to external" in find or "Form data submitted to external" in find:
            warning_indicators.append("✓ Login form submits sensitive credentials cross-domain")
        elif "Login form detected" in find:
            warning_indicators.append("✓ Authentication / Password input form present on page")
        elif "Suspicious JavaScript" in find:
            warning_indicators.append("✓ Obfuscated or suspicious JavaScript code detected")

    # 3. Text / NLP Analysis
    for find in text_res.get("findings", []):
        if "social engineering" in find or "credential request" in find or "Financial lure" in find:
            warning_indicators.append(f"✓ {find}")
        elif "No coercive" in find:
            positive_indicators.append("✓ Clean body text with no coercive phishing language")

    # 4. Domain Analysis
    for find in domain_res.get("findings", []):
        if "very recently registered" in find or "relatively new" in find:
            warning_indicators.append(f"✓ {find}")
        elif "well-established" in find:
            positive_indicators.append(f"✓ {find}")

    # 5. Brand Impersonation
    for find in brand_res.get("findings", []):
        if "Possible brand impersonation" in find or "does not match official brand" in find:
            warning_indicators.append(f"✓ {find}")
        elif "confirmed as official domain" in find:
            positive_indicators.append(f"✓ {find}")

    # 6. SSL Analysis
    for find in ssl_res.get("findings", []):
        if "Valid HTTPS / SSL certificate" in find:
            positive_indicators.append("✓ Valid HTTPS SSL certificate issued by trusted Authority")
        elif "unencrypted HTTP" in find or "SSL Certificate Verification Failed" in find:
            warning_indicators.append("✓ SSL / TLS encryption concerns")

    # Combine into main explanation list
    reasons = warning_indicators + positive_indicators
    if not reasons:
        reasons = ["✓ Automated heuristic evaluation completed."]

    # Summary generator
    if classification == "PHISHING":
        summary = f"High-risk phishing indicators detected. The system computed a risk score of {final_risk_score}/100 with {confidence}% confidence. Do not enter credentials or personal information."
    elif classification == "SUSPICIOUS":
        summary = f"Suspicious characteristics found. The website exhibits abnormal features (Risk Score: {final_risk_score}/100). Exercise caution before interacting."
    else:
        summary = f"The website appears legitimate with low risk indicators (Risk Score: {final_risk_score}/100). Standard security checks passed."

    return {
        "classification": classification,
        "risk_score": final_risk_score,
        "confidence": confidence,
        "risk_level": risk_level,
        "summary": summary,
        "reasons": reasons,
        "positive_indicators": positive_indicators,
        "warning_indicators": warning_indicators,
        "weights": weights
    }
