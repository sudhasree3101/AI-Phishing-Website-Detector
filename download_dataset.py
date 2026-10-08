"""
Dataset Download Script
========================
Downloads the PhiUSIIL Phishing URL Dataset from the UCI ML Repository.
Run this once before training.

Usage:
    python download_dataset.py
"""

import os
import sys
import zipfile
import urllib.request

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_RAW_DIR = os.path.join(ROOT_DIR, 'data', 'raw')
DATASET_CSV = os.path.join(DATA_RAW_DIR, 'PhiUSIIL_Phishing_URL_Dataset.csv')
DATASET_ZIP = os.path.join(DATA_RAW_DIR, 'phiusiil_phishing_url_dataset.zip')

UCI_DOWNLOAD_URL = (
    "https://archive.ics.uci.edu/static/public/967/"
    "phiusiil+phishing+url+dataset.zip"
)


def download():
    os.makedirs(DATA_RAW_DIR, exist_ok=True)

    if os.path.exists(DATASET_CSV):
        size_mb = os.path.getsize(DATASET_CSV) / (1024 * 1024)
        print(f"[OK] Dataset already present ({size_mb:.1f} MB): {DATASET_CSV}")
        return

    print("=" * 60)
    print("  PhiUSIIL Dataset Downloader")
    print("=" * 60)
    print(f"\nSource:  {UCI_DOWNLOAD_URL}")
    print(f"Target:  {DATASET_CSV}")
    print("\nDownloading (14.7 MB compressed, ~54 MB uncompressed)...\n")

    def reporthook(count, block_size, total_size):
        if total_size > 0:
            pct = min(100, int(count * block_size * 100 / total_size))
            done = count * block_size / (1024 * 1024)
            total = total_size / (1024 * 1024)
            bar = '#' * (pct // 5) + '-' * (20 - pct // 5)
            print(f"\r  [{bar}] {pct:3d}%  {done:.1f}/{total:.1f} MB", end='', flush=True)

    try:
        urllib.request.urlretrieve(UCI_DOWNLOAD_URL, DATASET_ZIP, reporthook)
        print("\n\n[OK] Download complete!")
    except Exception as e:
        print(f"\n\n[ERROR] Download failed: {e}")
        print("\nAlternative: Download manually from:")
        print(f"  https://archive.ics.uci.edu/dataset/967/phiusiil-phishing-url-dataset")
        print(f"Save the zip to: {DATASET_ZIP}")
        sys.exit(1)

    print("Extracting archive...")
    try:
        with zipfile.ZipFile(DATASET_ZIP, 'r') as zf:
            members = zf.namelist()
            print(f"  Archive contents: {members}")
            csv_files = [m for m in members if m.lower().endswith('.csv')]
            if not csv_files:
                print("[ERROR] No CSV file found in archive!")
                sys.exit(1)
            for csv_file in csv_files:
                zf.extract(csv_file, DATA_RAW_DIR)
                extracted_path = os.path.join(DATA_RAW_DIR, csv_file)
                # Normalize to expected filename
                if extracted_path != DATASET_CSV:
                    if os.path.exists(DATASET_CSV):
                        os.remove(DATASET_CSV)
                    os.rename(extracted_path, DATASET_CSV)
                print(f"  Extracted: {csv_file} -> PhiUSIIL_Phishing_URL_Dataset.csv")
    except Exception as e:
        print(f"[ERROR] Extraction failed: {e}")
        sys.exit(1)

    size_mb = os.path.getsize(DATASET_CSV) / (1024 * 1024)
    print(f"\n[OK] Dataset ready: {DATASET_CSV}")
    print(f"  Size: {size_mb:.1f} MB")
    print("\nNext step - train the model:")
    print("  python training/train_model.py")


if __name__ == '__main__':
    download()
