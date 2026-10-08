"""
Legacy training script redirect.
The actual training pipeline is now at: training/train_model.py

Usage:
    cd AI-Phishing-Website-Detector
    python training/train_model.py
"""
import os
import sys

if __name__ == '__main__':
    new_script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'training', 'train_model.py'
    )
    print(f"Redirecting to new training script: {new_script}")
    print("Please run: python training/train_model.py from the project root.\n")
    # Execute the new training script
    os.execv(sys.executable, [sys.executable, new_script] + sys.argv[1:])
