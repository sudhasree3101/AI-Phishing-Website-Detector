# Machine Learning Training Dataset Guide

This directory contains the dataset used to train the Random Forest classification model for URL phishing detection.

## Dataset File Location
- **Path:** `data/sample_urls.csv`

## Dataset Format & Specification
The dataset must be in CSV format with two mandatory columns:

| Column Name | Type | Description |
| :--- | :--- | :--- |
| `url` | String | Complete target URL string (e.g. `https://google.com` or `http://paypal-login-security.xyz/verify`) |
| `label` | Integer | Binary classification target: `0` for Legitimate websites, `1` for Phishing websites. |

## Example Dataset Rows
```csv
url,label
https://google.com,0
https://github.com,0
https://paypal.com,0
http://paypal-login-security.xyz/verify,1
http://192.168.1.1/admin/login.php,1
http://secure-update-paypal.account-verify.top/login,1
```

## How to Train / Re-train Model
To re-train the Random Forest classifier using updated dataset entries, run:

```bash
python backend/ml/train_model.py
```

The script will:
1. Extract 17 numerical URL structural features.
2. Perform train/test split.
3. Train Random Forest model.
4. Output Accuracy, Precision, Recall, F1 Score, and Confusion Matrix.
5. Save the trained model binary to `backend/ml/model.pkl`.
