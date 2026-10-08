"""
Backend ML Feature Extraction — PhiUSIIL v3 (Strict Parity)
=============================================================
This module IMPORTS from the shared src/feature_extraction.py module.
The backend and training pipeline use the IDENTICAL feature extractor.

Do NOT add feature logic here — add it to src/feature_extraction.py instead.
"""

import os
import sys

# Add project root to path so we can import from src/
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Re-export everything from the shared module
from src.feature_extraction import (  # noqa: F401
    extract_features,
    get_feature_metadata,
    FEATURE_NAMES,
    TLD_LEGIT_PROB,
)

__all__ = [
    'extract_features',
    'get_feature_metadata',
    'FEATURE_NAMES',
    'TLD_LEGIT_PROB',
]
