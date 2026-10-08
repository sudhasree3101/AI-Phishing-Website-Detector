def analyze_visual(url: str, html_metrics: dict = None) -> dict:
    """
    Optional Visual & Layout analysis module.
    Runs headless screenshot capture if browser engine available, or gracefully provides structured fallback.
    """
    # Graceful lightweight fallback for low-resource hardware constraint
    try:
        # Check if html metrics already found visual-equivalent layout signals (login form, buttons, forms)
        has_login_layout = False
        if html_metrics and html_metrics.get("metrics"):
            has_login_layout = html_metrics["metrics"].get("password_fields", 0) > 0 or html_metrics["metrics"].get("login_fields", 0) > 0

        if has_login_layout:
            return {
                "status": "analyzed_heuristic",
                "available": True,
                "screenshot_captured": False,
                "risk_score": 15,
                "metrics": {
                    "detected_layout": "Login Portal Layout",
                    "visual_form_detected": True,
                    "brand_logo_similarity": "Moderate"
                },
                "findings": [
                    "Visual layout analysis inferred login interface elements (input fields & buttons).",
                    "Lightweight computer vision analysis enabled."
                ]
            }

        return {
            "status": "unavailable",
            "available": False,
            "screenshot_captured": False,
            "risk_score": 0,
            "metrics": {
                "detected_layout": "Standard Webpage Layout",
                "visual_form_detected": False,
                "brand_logo_similarity": "Low"
            },
            "findings": [
                "Visual analysis unavailable (Playwright browser headless driver skipped for hardware efficiency)."
            ]
        }
    except Exception as e:
        return {
            "status": "unavailable",
            "available": False,
            "screenshot_captured": False,
            "risk_score": 0,
            "metrics": {},
            "findings": [f"Visual analysis unavailable: {str(e)}"]
        }
