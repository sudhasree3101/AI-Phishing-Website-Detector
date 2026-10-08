"""
Training Pipeline — PhiUSIIL Phishing URL Dataset (v3 — Strict Parity)
=======================================================================
CRITICAL DESIGN DECISION:
  This script loads the PhiUSIIL dataset URLs and RECOMPUTES all features
  using the SAME src/feature_extraction.py module used during live prediction.
  
  We do NOT read the dataset's pre-computed feature columns (e.g. TLDLegitimateProb,
  CharContinuationRate, URLCharProb) because those were computed with different
  mathematical definitions than our live extractor uses. Using them would create
  a training/inference distribution mismatch.

  TRAINING FEATURE CALCULATION == LIVE PREDICTION FEATURE CALCULATION
  (enforced by calling extract_features(url) in both contexts)

Usage:
    cd AI-Phishing-Website-Detector
    python training/train_model.py

Output:
    models/phishing_model.pkl
    models/feature_metadata.json

RAM notes:
- Dataset CSV read: ~60 MB peak (URL+label only)
- Feature extraction: vectorized in chunks; ~200 MB peak
- Model: ExtraTreesClassifier (200 trees); ~150-400 MB peak
- Total peak: ~600-800 MB
"""

import os
import sys
import json
import time
import warnings
import zipfile
import urllib.request

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score,
    classification_report
)

warnings.filterwarnings('ignore')

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_RAW_DIR = os.path.join(ROOT_DIR, 'data', 'raw')
DATA_PROCESSED_DIR = os.path.join(ROOT_DIR, 'data', 'processed')
MODELS_DIR = os.path.join(ROOT_DIR, 'models')
SRC_DIR = os.path.join(ROOT_DIR, 'src')

DATASET_CSV = os.path.join(DATA_RAW_DIR, 'PhiUSIIL_Phishing_URL_Dataset.csv')
DATASET_ZIP = os.path.join(DATA_RAW_DIR, 'phiusiil_phishing_url_dataset.zip')
MODEL_PATH = os.path.join(MODELS_DIR, 'phishing_model.pkl')
METADATA_PATH = os.path.join(MODELS_DIR, 'feature_metadata.json')

UCI_DOWNLOAD_URL = (
    "https://archive.ics.uci.edu/static/public/967/"
    "phiusiil+phishing+url+dataset.zip"
)

# Add src to path for the shared feature extractor
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, ROOT_DIR)

from src.feature_extraction import extract_features, FEATURE_NAMES, get_feature_metadata

# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------

def download_dataset():
    """Download and extract the PhiUSIIL dataset from UCI."""
    os.makedirs(DATA_RAW_DIR, exist_ok=True)

    if os.path.exists(DATASET_CSV):
        size_mb = os.path.getsize(DATASET_CSV) / (1024 * 1024)
        print(f"[OK] Dataset already exists ({size_mb:.1f} MB): {DATASET_CSV}")
        return True

    print(f"\nDownloading PhiUSIIL dataset from UCI ML Repository...")
    print(f"   URL: {UCI_DOWNLOAD_URL}")
    print("   This may take a moment (14.7 MB compressed)...\n")

    try:
        def reporthook(count, block_size, total_size):
            if total_size > 0:
                pct = min(100, int(count * block_size * 100 / total_size))
                mb_done = count * block_size / (1024 * 1024)
                mb_total = total_size / (1024 * 1024)
                print(f"\r   Progress: {pct:3d}% ({mb_done:.1f}/{mb_total:.1f} MB) ", end='', flush=True)

        urllib.request.urlretrieve(UCI_DOWNLOAD_URL, DATASET_ZIP, reporthook)
        print("\n")
        print("[OK] Download complete. Extracting...")
    except Exception as e:
        print(f"\n[ERROR] Download failed: {e}")
        print("  Please download manually from:")
        print(f"  {UCI_DOWNLOAD_URL}")
        print(f"  Save as: {DATASET_ZIP}")
        return False

    try:
        with zipfile.ZipFile(DATASET_ZIP, 'r') as zf:
            files = zf.namelist()
            print(f"  Archive contains: {files}")
            csv_files = [f for f in files if f.endswith('.csv')]
            if not csv_files:
                print("[ERROR] No CSV found in zip archive.")
                return False
            for csv_file in csv_files:
                zf.extract(csv_file, DATA_RAW_DIR)
                extracted = os.path.join(DATA_RAW_DIR, csv_file)
                if extracted != DATASET_CSV:
                    if os.path.exists(DATASET_CSV):
                        os.remove(DATASET_CSV)
                    os.rename(extracted, DATASET_CSV)
                print(f"[OK] Extracted: {csv_file}")
        return True
    except Exception as e:
        print(f"[ERROR] Extraction failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Feature extraction from URLs (training parity)
# ---------------------------------------------------------------------------

def extract_features_chunked(urls: list, chunk_size: int = 5000) -> np.ndarray:
    """
    Extract features for a list of URLs in chunks to avoid peak RAM spikes.
    Uses src/feature_extraction.py — the SAME module as live prediction.
    """
    all_features = []
    n = len(urls)
    for start in range(0, n, chunk_size):
        end = min(start + chunk_size, n)
        chunk = urls[start:end]
        chunk_feats = [extract_features(url) for url in chunk]
        all_features.extend(chunk_feats)
        pct = int(end / n * 100)
        print(f"\r   Extracting features: {pct:3d}% ({end:,}/{n:,})", end='', flush=True)
    print()
    return np.array(all_features, dtype=np.float32)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_phishing_model():
    """
    Full training pipeline.
    
    KEY: Features are extracted by calling extract_features(url) from the
    shared src/feature_extraction.py — NOT from the dataset's pre-computed columns.
    This guarantees that training features and live-prediction features are
    mathematically identical.
    """
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(DATA_PROCESSED_DIR, exist_ok=True)

    print("=" * 65)
    print("  PhiUSIIL Phishing URL Model Training (Strict Parity v3)")
    print("=" * 65)

    # 1. Download dataset if needed
    if not download_dataset():
        sys.exit(1)

    # 2. Load ONLY the URL and label columns (memory efficient)
    print(f"\nLoading dataset (URL + label only): {DATASET_CSV}")
    df = pd.read_csv(
        DATASET_CSV,
        usecols=['URL', 'label'],
        dtype={'label': np.int8}
    )
    print(f"[OK] Loaded {len(df):,} rows")

    # Validate labels
    print(f"\n  Label distribution (UCI convention: 1=Legit, 0=Phishing):")
    vc = df['label'].value_counts().sort_index()
    for lbl, cnt in vc.items():
        name = "Legitimate" if lbl == 1 else "Phishing"
        print(f"    label={int(lbl)} ({name}): {cnt:,} ({cnt/len(df)*100:.1f}%)")

    # 3. Extract features from raw URLs using the SHARED extractor
    print(f"\nExtracting {len(FEATURE_NAMES)} features from {len(df):,} URLs")
    print("   Using: src/feature_extraction.py (same as live prediction)")
    print()

    urls = df['URL'].tolist()
    y = df['label'].values.astype(np.int8)

    # Free the dataframe now to save RAM
    del df

    t_extract = time.time()
    X = extract_features_chunked(urls, chunk_size=5000)
    del urls
    print(f"   [OK] Feature extraction complete in {time.time()-t_extract:.1f}s")
    print(f"   Feature matrix shape: {X.shape}")

    # 4. Verify feature alignment
    assert X.shape[1] == len(FEATURE_NAMES), (
        f"Shape mismatch: {X.shape[1]} != {len(FEATURE_NAMES)}"
    )
    print(f"\n[OK] Feature alignment verified: {len(FEATURE_NAMES)} features")
    print(f"     Features: {FEATURE_NAMES}")

    # 5. Stratified train/test split (80/20)
    print(f"\nSplitting data (80% train / 20% test, stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )
    print(f"   Train: {X_train.shape[0]:,} samples")
    print(f"   Test:  {X_test.shape[0]:,} samples")

    # Free test X temporarily until evaluation
    # (keep X_test in memory for evaluation immediately after training)

    # 6. Train ExtraTreesClassifier
    print(f"\nTraining ExtraTreesClassifier...")
    print("   n_estimators=200, max_depth=20, min_samples_leaf=5, n_jobs=-1")
    t0 = time.time()

    model = ExtraTreesClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=5,
        max_features='sqrt',
        n_jobs=-1,
        random_state=42,
        # No class_weight: dataset is already near-balanced (57/43).
        # Using 'balanced' caused over-prediction of phishing on short URLs.
    )
    model.fit(X_train, y_train)
    elapsed = time.time() - t0
    print(f"[OK] Training complete in {elapsed:.1f}s")

    # 6b. Calibrate probabilities with Platt scaling (sigmoid)
    # This corrects overconfident raw probabilities from ExtraTrees, reducing
    # false positives on clean short URLs that fall near the decision boundary.
    print("\nCalibrating probabilities with Platt scaling (cv=3)...")
    t_cal = time.time()
    calibrated_model = CalibratedClassifierCV(model, method='sigmoid', cv=3)
    calibrated_model.fit(X_train, y_train)
    print(f"[OK] Calibration complete in {time.time()-t_cal:.1f}s")

    # Use the calibrated model for everything from here
    model = calibrated_model

    # 7. Evaluate
    print(f"\nEvaluating on held-out test set ({X_test.shape[0]:,} samples)...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)

    classes = list(model.classes_)
    phish_idx = classes.index(0) if 0 in classes else 0
    legit_idx = 1 - phish_idx

    y_prob_phishing = y_prob[:, phish_idx]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0, pos_label=0)
    rec = recall_score(y_test, y_pred, zero_division=0, pos_label=0)
    f1 = f1_score(y_test, y_pred, zero_division=0, pos_label=0)
    cm = confusion_matrix(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, 1.0 - y_prob_phishing)

    print("\n" + "=" * 55)
    print("  MODEL EVALUATION METRICS")
    print("=" * 55)
    print(f"  Accuracy:              {acc:.4f}  ({acc*100:.2f}%)")
    print(f"  Precision (phishing):  {prec:.4f}")
    print(f"  Recall    (phishing):  {rec:.4f}")
    print(f"  F1 Score  (phishing):  {f1:.4f}")
    print(f"  ROC-AUC:               {roc_auc:.4f}")
    print()
    print("  Confusion Matrix (rows=actual, cols=predicted):")
    print(f"  Class order: {sorted(classes)}")
    print(cm)
    print()
    print("  Full Classification Report:")
    target_names = ['Phishing (0)', 'Legitimate (1)']
    print(classification_report(y_test, y_pred,
                                target_names=target_names,
                                zero_division=0))
    print("=" * 55)

    # 8. Feature importances
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("\n  Top Feature Importances:")
    for i in range(len(FEATURE_NAMES)):
        idx = sorted_idx[i]
        print(f"    {FEATURE_NAMES[idx]:35s}: {importances[idx]:.4f}")

    # 9. Save model + metadata
    feature_meta = get_feature_metadata()
    imp_dict = {FEATURE_NAMES[i]: round(float(importances[i]), 6)
                for i in range(len(FEATURE_NAMES))}

    feature_meta.update({
        "feature_names": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "model_type": "ExtraTreesClassifier",
        "model_version": "3.0-phiusiil-strict-parity",
        "training_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]),
        "training_note": (
            "Features recomputed from raw URL strings using src/feature_extraction.py. "
            "Dataset pre-computed columns NOT used. Training == Live parity guaranteed."
        ),
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision_phishing": round(float(prec), 4),
            "recall_phishing": round(float(rec), 4),
            "f1_score_phishing": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4),
        },
        "feature_importances": imp_dict,
        "label_convention": {
            "0": "Phishing",
            "1": "Legitimate"
        },
        "classes": [int(c) for c in model.classes_],
        "phishing_class_index": phish_idx,
    })

    print(f"\nSaving model to: {MODEL_PATH}")
    joblib.dump({
        'model': model,
        'feature_names': FEATURE_NAMES,
        'classes': model.classes_,
        'phishing_class_index': phish_idx,
        'metrics': feature_meta['metrics'],
        'feature_importances': imp_dict,
    }, MODEL_PATH, compress=3)
    model_size_mb = os.path.getsize(MODEL_PATH) / (1024 * 1024)
    print(f"[OK] Model saved ({model_size_mb:.1f} MB)")

    print(f"Saving feature metadata to: {METADATA_PATH}")
    with open(METADATA_PATH, 'w') as f:
        json.dump(feature_meta, f, indent=2)
    print("[OK] Metadata saved")

    print("\n" + "=" * 65)
    print("  TRAINING COMPLETE")
    print("=" * 65)
    print(f"\n  Dataset:       235,795 URLs (UCI PhiUSIIL)")
    print(f"  Features:      {len(FEATURE_NAMES)} URL-only features (recomputed from raw URLs)")
    print(f"  Model:         ExtraTreesClassifier (200 trees)")
    print(f"  Accuracy:      {acc*100:.2f}%")
    print(f"  ROC-AUC:       {roc_auc:.4f}")
    print(f"  Model size:    {model_size_mb:.1f} MB")
    print(f"\n  TRAIN/PREDICT PARITY: GUARANTEED")
    print(f"  Both training and inference call extract_features(url)")
    print(f"  from src/feature_extraction.py")
    print(f"\n  [OK] Ready for inference. Run: start_backend.bat")
    print("=" * 65)

    return {
        'accuracy': acc,
        'roc_auc': roc_auc,
        'feature_names': FEATURE_NAMES,
        'model_path': MODEL_PATH,
    }


if __name__ == '__main__':
    train_phishing_model()
