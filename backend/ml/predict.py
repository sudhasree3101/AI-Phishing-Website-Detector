"""
ML Prediction Module — PhiUSIIL v2
====================================
Loads the trained model once at startup, validates feature alignment,
and runs inference on new URLs.

UCI label convention: 0 = Phishing, 1 = Legitimate
"""

import os
import sys
import json
import logging

import numpy as np
import joblib

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)

# Add project root so src/ is importable
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from ml.feature_extraction import extract_features, FEATURE_NAMES, get_feature_metadata

# Primary model path (new location)
MODEL_PATH = os.path.join(_PROJECT_ROOT, 'models', 'phishing_model.pkl')
METADATA_PATH = os.path.join(_PROJECT_ROOT, 'models', 'feature_metadata.json')

# Fallback to old location for backwards compatibility
_LEGACY_MODEL_PATH = os.path.join(_BACKEND_DIR, 'ml', 'model.pkl')

# ---------------------------------------------------------------------------
# Model cache (loaded once at startup)
# ---------------------------------------------------------------------------
_model_cache = None
_metadata_cache = None


def _load_metadata() -> dict:
    """Load feature metadata JSON for validation."""
    global _metadata_cache
    if _metadata_cache is not None:
        return _metadata_cache

    if os.path.exists(METADATA_PATH):
        with open(METADATA_PATH, 'r') as f:
            _metadata_cache = json.load(f)
        return _metadata_cache
    return {}


def load_saved_model() -> dict | None:
    """Load model from disk once, cache in memory."""
    global _model_cache

    if _model_cache is not None:
        return _model_cache

    # Try new model path first
    path = MODEL_PATH if os.path.exists(MODEL_PATH) else _LEGACY_MODEL_PATH

    if not os.path.exists(path):
        logger.warning(
            f"No trained model found at {MODEL_PATH}. "
            "Run: python training/train_model.py"
        )
        return None

    try:
        data = joblib.load(path)
        # Validate feature alignment if metadata available
        if 'feature_names' in data:
            stored_names = data['feature_names']
            if stored_names != FEATURE_NAMES:
                logger.error(
                    "FEATURE MISMATCH DETECTED!\n"
                    f"Model was trained on features: {stored_names}\n"
                    f"Current extractor features: {FEATURE_NAMES}\n"
                    "Retrain the model: python training/train_model.py"
                )
                return None
        _model_cache = data
        model_source = "new (PhiUSIIL)" if path == MODEL_PATH else "legacy"
        logger.info(f"Model loaded from {path} ({model_source})")
        return _model_cache
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return None


def _get_feature_explanations(features: list, importances: dict) -> list[str]:
    """
    Generate human-readable explanation strings based on actual feature values
    and their importances. Returns top reasons for the classification.
    """
    reasons = []

    feat_map = dict(zip(FEATURE_NAMES, features))

    # Sort features by importance (descending)
    sorted_features = sorted(
        importances.items(),
        key=lambda x: x[1],
        reverse=True
    )

    for feat_name, imp in sorted_features:
        if imp < 0.01:  # skip low-importance features
            continue
        val = feat_map.get(feat_name, 0)

        # Phishing indicators (positive = suspicious)
        if feat_name == 'URLLength' and val > 75:
            reasons.append(f"Unusually long URL ({int(val)} characters)")
        elif feat_name == 'URLLength' and val > 54:
            reasons.append(f"Above-average URL length ({int(val)} characters)")
        elif feat_name == 'IsDomainIP' and val == 1.0:
            reasons.append("URL uses raw IP address instead of domain name")
        elif feat_name == 'TLDLegitimateProb' and val < 0.25:
            reasons.append(f"High-risk TLD with low legitimacy score ({val:.2f})")
        elif feat_name == 'TLDLegitimateProb' and val < 0.5:
            reasons.append(f"Suspicious TLD with below-average legitimacy ({val:.2f})")
        elif feat_name == 'TLDLegitimateProb' and val >= 0.85:
            reasons.append(f"Well-known legitimate TLD (legitimacy score: {val:.2f})")
        elif feat_name == 'NoOfSubDomain' and val >= 3:
            reasons.append(f"Excessive number of subdomains ({int(val)})")
        elif feat_name == 'NoOfSubDomain' and val == 2:
            reasons.append("Multiple subdomains detected")
        elif feat_name == 'HasObfuscation' and val == 1.0:
            reasons.append(f"URL contains obfuscated/encoded characters ({int(feat_map.get('NoOfObfuscatedChar',0))})")
        elif feat_name == 'IsHTTPS' and val == 0.0:
            reasons.append("URL uses insecure HTTP (no SSL/TLS)")
        elif feat_name == 'IsHTTPS' and val == 1.0:
            reasons.append("URL uses secure HTTPS protocol")
        elif feat_name == 'CharContinuationRate' and val > 0.08:
            reasons.append("Suspicious repetitive character pattern in URL")
        elif feat_name == 'URLCharProb' and val < 0.88:
            reasons.append("Unusual character distribution in URL (possible obfuscation)")
        elif feat_name == 'DegitRatioInURL' and val > 0.2:
            reasons.append(f"High proportion of digits in URL ({val*100:.0f}%)")
        elif feat_name == 'NoOfEqualsInURL' and val > 3:
            reasons.append(f"Many query parameters ({int(val)} '=' signs)")
        elif feat_name == 'SpacialCharRatioInURL' and val > 0.05:
            reasons.append(f"High ratio of special characters ({val*100:.1f}%)")
        elif feat_name == 'Bank' and val == 1.0:
            reasons.append("Banking-related keyword found in URL")
        elif feat_name == 'Pay' and val == 1.0:
            reasons.append("Payment-related keyword found in URL")
        elif feat_name == 'Crypto' and val == 1.0:
            reasons.append("Cryptocurrency-related keyword found in URL")
        elif feat_name == 'DomainLength' and val > 30:
            reasons.append(f"Unusually long domain name ({int(val)} characters)")

    if not reasons:
        reasons.append("No strongly suspicious URL characteristics detected")

    return reasons[:6]  # return top 6 reasons max


def predict_url_phishing(url: str) -> dict:
    """
    Predict phishing probability for a URL using the trained ML model.

    The model is loaded once and cached. Features are extracted using the
    same shared module used during training.

    Returns
    -------
    dict with keys: status, phishing_probability, confidence, top_features,
                    prediction_label, metrics
    """
    # 1. Extract features using shared extractor
    features = extract_features(url)
    features_arr = np.array(features, dtype=np.float32).reshape(1, -1)

    # 2. Load model
    model_data = load_saved_model()

    if model_data and 'model' in model_data:
        model = model_data['model']
        stored_features = model_data.get('feature_names', FEATURE_NAMES)

        # Validate feature count
        if len(features) != len(stored_features):
            return {
                "status": "feature_mismatch_error",
                "error": (
                    f"Feature count mismatch: extractor produced {len(features)} "
                    f"but model expects {len(stored_features)}. "
                    "Retrain the model."
                ),
                "phishing_probability": 50.0,
                "confidence": 0.0,
                "top_features": [],
            }

        # 3. Run inference
        probs = model.predict_proba(features_arr)[0]
        classes = list(model.classes_)

        # UCI convention: class 0 = Phishing, class 1 = Legitimate
        phish_idx = model_data.get('phishing_class_index', 0)
        phishing_prob = float(probs[phish_idx])
        legit_prob = 1.0 - phishing_prob
        confidence = float(np.max(probs))

        # Use a slightly conservative phishing threshold (0.55 instead of 0.5)
        # This reduces false positives on short simple legitimate URLs without
        # meaningfully impacting detection of clearly phishing URLs (>80%)
        PHISHING_THRESHOLD = 0.55
        prediction_label = "Phishing" if phishing_prob >= PHISHING_THRESHOLD else "Legitimate"

        # 4. Feature importance (global model importances applied to this URL)
        importances = model_data.get('feature_importances', {})
        if not importances:
            raw_imps = model.feature_importances_
            importances = {FEATURE_NAMES[i]: float(raw_imps[i]) for i in range(len(FEATURE_NAMES))}

        top_features = []
        sorted_feat = sorted(importances.items(), key=lambda x: x[1], reverse=True)
        for feat_name, imp in sorted_feat[:7]:
            feat_idx = FEATURE_NAMES.index(feat_name) if feat_name in FEATURE_NAMES else -1
            feat_val = features[feat_idx] if feat_idx >= 0 else 0.0
            top_features.append({
                "feature": feat_name,
                "value": round(feat_val, 4),
                "importance": round(imp, 4),
            })

        # 5. Generate explanations
        reasons = _get_feature_explanations(features, importances)

        return {
            "status": "model_prediction",
            "prediction_label": prediction_label,
            "phishing_probability": round(phishing_prob * 100, 2),
            "legitimate_probability": round(legit_prob * 100, 2),
            "confidence": round(confidence * 100, 2),
            "top_features": top_features,
            "reasons": reasons,
            "metrics": model_data.get('metrics', {}),
        }

    else:
        # ----- Heuristic fallback (no trained model yet) -----
        feat_map = dict(zip(FEATURE_NAMES, features))
        url_len = feat_map.get('URLLength', 0)
        is_ip = feat_map.get('IsDomainIP', 0)
        tld_prob = feat_map.get('TLDLegitimateProb', 0.5)
        subdomains = feat_map.get('NoOfSubDomain', 0)
        is_https = feat_map.get('IsHTTPS', 0)
        has_obfusc = feat_map.get('HasObfuscation', 0)

        score = 0
        score += (url_len > 75) * 20
        score += is_ip * 35
        score += (tld_prob < 0.25) * 30
        score += (tld_prob < 0.5) * 10
        score += (subdomains >= 3) * 20
        score += (1 - is_https) * 15
        score += has_obfusc * 15

        phishing_prob = min(1.0, score / 100.0)
        prediction_label = "Phishing" if phishing_prob > 0.5 else "Legitimate"

        reasons = _get_feature_explanations(features, {
            fn: 1.0 / len(FEATURE_NAMES) for fn in FEATURE_NAMES
        })

        return {
            "status": "heuristic_fallback",
            "prediction_label": prediction_label,
            "phishing_probability": round(phishing_prob * 100, 2),
            "legitimate_probability": round((1 - phishing_prob) * 100, 2),
            "confidence": 75.0,
            "top_features": [
                {"feature": "URLLength", "value": url_len, "importance": 0.20},
                {"feature": "IsDomainIP", "value": is_ip, "importance": 0.35},
                {"feature": "TLDLegitimateProb", "value": tld_prob, "importance": 0.25},
                {"feature": "IsHTTPS", "value": is_https, "importance": 0.15},
            ],
            "reasons": reasons,
            "metrics": {"note": "Heuristic fallback — train the model first."},
        }
