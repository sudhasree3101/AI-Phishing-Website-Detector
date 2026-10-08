# AI-Powered Phishing Website Detector

A complete, end-to-end cybersecurity analysis application that uses Machine Learning, NLP, URL structural analysis, HTML inspection, Domain WHOIS, SSL certificate inspection, and Brand Impersonation detection to assess whether a website is **legitimate**, **suspicious**, or a **phishing** site.

---

## Problem Statement

Phishing websites impersonate trusted brands to steal credentials, payment details, and personal information. Simple URL blacklists miss zero-day phishing attacks. This application uses **multi-signal Explainable AI** to analyze websites from seven distinct perspectives and explain *why* something is flagged.

---

## Key Features

| Feature | Description |
| :--- | :--- |
| **URL Analysis** | 20+ structural heuristics: length, entropy, hyphens, TLD risk, IP usage, @-symbols |
| **Machine Learning** | Trained Random Forest classifier on URL feature vectors |
| **HTML Analysis** | Inspects forms, password fields, cross-domain submissions, iframes, JavaScript |
| **NLP Text Analysis** | Detects urgency language, credential requests, and financial lures |
| **Brand Impersonation** | Compares domain against 11 official brand domains |
| **Domain / WHOIS** | Checks registration age, registrar, and nameservers |
| **SSL Analysis** | Verifies certificate validity, issuer, expiry, and hostname match |
| **Explainable AI** | Every score is justified with plain-English reasons |
| **Demo Mode** | Pre-built phishing / suspicious / legitimate presets for offline demonstration |

---

## Technology Stack

**Backend**
- Python 3.10+
- FastAPI + Uvicorn
- Scikit-learn (Random Forest)
- BeautifulSoup4 (HTML parsing)
- python-whois (Domain registration)
- Requests (Safe HTTP fetching with SSRF protection)
- Joblib (Model serialization)

**Frontend**
- React 18
- Vite 4
- Lucide React (icons)
- Vanilla CSS (custom cybersecurity dark theme)

---

## Project Structure

```
AI-Phishing-Website-Detector/
├── backend/
│   ├── main.py                   ← FastAPI app entry point
│   ├── requirements.txt
│   ├── api/
│   │   └── routes.py             ← API routes: /analyze, /health, /
│   ├── services/
│   │   ├── url_analyzer.py       ← URL structural feature analysis
│   │   ├── html_analyzer.py      ← HTML element and form inspection
│   │   ├── text_analyzer.py      ← NLP + social engineering detection
│   │   ├── domain_analyzer.py    ← WHOIS & DNS domain checks
│   │   ├── ssl_analyzer.py       ← SSL certificate inspection
│   │   ├── brand_detector.py     ← Brand impersonation detection
│   │   ├── visual_analyzer.py    ← Lightweight visual layout heuristic
│   │   └── risk_engine.py        ← Multi-signal aggregation + Explainable AI
│   ├── ml/
│   │   ├── feature_extraction.py ← 17-feature URL vector extractor
│   │   ├── train_model.py        ← Training pipeline: RF + evaluation
│   │   ├── predict.py            ← Inference + feature importance
│   │   └── model.pkl             ← Pre-trained Random Forest model
│   └── utils/
│       └── helpers.py            ← SSRF protection, safe HTTP fetch
│
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── App.jsx               ← Main state management + API calls
│       ├── main.jsx
│       ├── components/
│       │   ├── Navbar.jsx
│       │   ├── UrlInput.jsx      ← URL entry form + demo presets
│       │   ├── SecurityGauge.jsx ← Conic gradient risk gauge
│       │   ├── RiskScore.jsx     ← Classification badge + confidence
│       │   ├── AnalysisCard.jsx  ← Individual module result card
│       │   ├── FeatureList.jsx   ← ML feature importance display
│       │   ├── LoadingAnimation.jsx ← Step-by-step analysis progress
│       │   └── ResultsDashboard.jsx ← Full results layout
│       └── styles/
│           └── app.css           ← Dark cybersecurity theme
│
├── data/
│   ├── sample_urls.csv           ← Training dataset (30 labelled URLs)
│   └── README.md                 ← Dataset format guide
│
├── .env.example                  ← Optional API key template
├── .gitignore
├── start_backend.bat             ← One-click Windows backend launcher
├── start_frontend.bat            ← One-click Windows frontend launcher
└── README.md                     ← This file
```

---

## Installation & Setup

### Prerequisites
- Python 3.10 or above
- Node.js 18+ and npm

### 1. Install Backend Dependencies

```bash
pip install -r backend/requirements.txt
```

### 2. Train the ML Model (already pre-trained, re-run to update)

```bash
python backend/ml/train_model.py
```

Output:
```
Accuracy:  1.0000
Precision: 1.0000
Recall:    1.0000
F1 Score:  1.0000
Model successfully saved to backend/ml/model.pkl
```

> Note: The sample dataset is small (30 URLs) for demonstration. Use a larger dataset like [PhishTank](https://www.phishtank.com/) or the [ISCX URL dataset](https://www.unb.ca/cic/datasets/) for better generalization.

### 3. Install Frontend Dependencies

```bash
cd frontend
npm install
```

### 4. Configure Environment (Optional)

Copy `.env.example` to `.env` and fill in optional API keys:

```bash
VIRUSTOTAL_API_KEY=your_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
```

The application works fully without these keys.

---

## Running the Application

### Option A: One-click Windows scripts

Double-click **`start_backend.bat`** (terminal 1), then **`start_frontend.bat`** (terminal 2).

### Option B: Manual startup

**Terminal 1 — Backend:**
```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
```

Open your browser at: **http://localhost:5173**

---

## API Documentation

The backend exposes an auto-generated Swagger UI at: **http://localhost:8000/docs**

### `POST /analyze`

**Request:**
```json
{
  "url": "https://paypal-login-security.xyz/verify",
  "is_demo": false
}
```

**Response:**
```json
{
  "url": "https://paypal-login-security.xyz/verify",
  "classification": "PHISHING",
  "risk_score": 92,
  "confidence": 96,
  "risk_level": "CRITICAL",
  "summary": "High-risk phishing indicators detected...",
  "reasons": ["✓ Suspicious TLD", "✓ Brand impersonation"],
  "url_analysis": { ... },
  "domain_analysis": { ... },
  "html_analysis": { ... },
  "nlp_analysis": { ... },
  "ssl_analysis": { ... },
  "brand_analysis": { ... },
  "visual_analysis": { ... },
  "feature_importance": [ ... ]
}
```

### Risk Level Reference

| Score | Level | Classification |
| :--- | :--- | :--- |
| 0 – 29 | LOW | LEGITIMATE |
| 30 – 59 | MEDIUM | SUSPICIOUS |
| 60 – 79 | HIGH | PHISHING |
| 80 – 100 | CRITICAL | PHISHING |

---

## Machine Learning Pipeline

**17 URL Feature Vector:**

```
url_length, domain_length, dot_count, hyphen_count, underscore_count,
special_char_count, digit_count, query_param_count, subdomains_count,
is_ip, is_https, has_at_symbol, is_shortened, is_suspicious_tld,
domain_entropy, keyword_count, brand_count
```

**Model:** Random Forest (100 estimators, max_depth=10)

**Training Data Format:** `data/sample_urls.csv`
```csv
url,label
https://google.com,0
http://paypal-login-security.xyz/verify,1
```

Labels: `0` = Legitimate, `1` = Phishing/Suspicious

---

## Security Design

- **SSRF Protection:** Private IPs (10.x, 192.168.x, 127.x), localhost, and `.local` domains are blocked.
- **Request timeouts:** 4-second hard timeout on all outbound HTTP requests.
- **Max response size:** Limited to 2 MB to prevent memory exhaustion.
- **No credentials collected:** The application inspects websites but never stores or transmits form data.
- **Error isolation:** Each analysis module runs independently. A failing module returns a graceful error, not a crash.

---

## Demo Mode

Three preset examples are built in. Click the **Quick Demo Presets** buttons or pass `"is_demo": true` in the API:

| Preset | Expected Result |
| :--- | :--- |
| PayPal Spoofing URL | PHISHING (Risk: 96) |
| Free Bonus URL | SUSPICIOUS (Risk: 52) |
| google.com | LEGITIMATE (Risk: 5) |

Demo results are clearly labelled as **DEMO PRESET RESULT** in the UI.

---

## Limitations

- ML model trained on a small sample dataset — accuracy will improve with more labeled data.
- WHOIS data is rate-limited and may be unavailable for some domains.
- Visual analysis is heuristic-based (no full browser rendering on low-end hardware).
- Some phishing sites may evade detection if they use clean URLs and load content dynamically.
- SSL validity does not guarantee a site is safe — this is explicitly communicated to users.

---

## Future Enhancements

- **Browser Extension** — Real-time warning overlay before visiting a flagged site.
- **Email Phishing Detection** — Analyze links and content inside email messages.
- **SMS / QR Phishing** — Decode QR code URLs and SMS link targets.
- **CLIP Visual Similarity** — Compare screenshot embeddings against official brand pages.
- **Transformer NLP** — DistilBERT or RoBERTa for more accurate social engineering text detection.
- **VirusTotal Integration** — Cross-reference against live threat intelligence databases.
- **Continuous Monitoring** — Schedule recurring checks and send alerts on status changes.
- **Enterprise Dashboard** — Multi-user, historical analysis, and export to PDF report.

---

## Example Output

```
Classification: PHISHING WEBSITE
Risk Score: 96/100
Confidence: 97%

Key Findings:
✓ Domain uses high-risk suspicious TLD (.xyz)
✓ Possible brand impersonation for PayPal
✓ Login form submits credentials cross-domain
✓ High urgency social engineering language
✓ Domain registered < 30 days ago
✓ Valid HTTPS certificate (recently issued)
```
