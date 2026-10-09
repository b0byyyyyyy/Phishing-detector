# PhishGuard — AI-Powered Phishing URL Detector (Prototype)

A small end-to-end machine learning project that detects whether a URL
is likely **phishing** or **legitimate**, with a web UI to demo it live.

Built for a classroom demo — everything runs locally, offline, with no
API keys or external services required.

## How it works

1. **`feature_extractor.py`** — turns any URL into 20 numeric/binary
   features (length, use of an IP address, suspicious keywords,
   suspicious top-level domains, hyphen count, HTTPS usage, etc.),
   without needing to visit the URL.
2. **`generate_dataset.py`** — builds a labeled dataset of ~1,200
   realistic legitimate and phishing-style URLs (synthetic, offline,
   deliberately includes some tricky/overlapping examples so the model
   isn't trivially "too perfect").
3. **`train_model.py`** — trains a `RandomForestClassifier`
   (scikit-learn) on the extracted features and reports accuracy,
   precision, recall, F1, a confusion matrix, and feature importances.
4. **`app.py`** + **`templates/`** + **`static/`** — a Flask web app
   where you paste in a URL and instantly see:
   - Verdict (phishing / legitimate) with a confidence score
   - A visual confidence gauge
   - Plain-English "signals detected" (why the model flagged it)
   - The raw feature values fed into the model

## Project structure

```
phishing-detector/
├── app.py                  # Flask web server
├── feature_extractor.py    # URL -> feature vector
├── generate_dataset.py     # builds data/urls.csv
├── train_model.py          # trains & evaluates the model
├── requirements.txt
├── data/
│   └── urls.csv            # generated training data
├── models/
│   ├── phishing_url_model.joblib
│   └── feature_names.joblib
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── app.js
```

## Setup & run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Already done, but to regenerate) build the dataset
python generate_dataset.py

# 3. (Already done, but to retrain) train the model
python train_model.py

# 4. Launch the web app
python app.py
```

Then open **http://localhost:5000** in your browser.

The trained model is already included in `models/`, so you can skip
straight to step 4 if you just want to run the demo.

## Demoing it to your teacher

- Point out the **Try:** sample links on the page for quick, reliable demos.
- Paste a real, obviously safe URL (e.g. `https://github.com`) to show a
  "legitimate" verdict.
- Paste a URL with a raw IP address, a suspicious domain suffix
  (`.tk`, `.xyz`), or words like "verify"/"login" in an odd place to
  show a "phishing" verdict.
- Open **"Raw extracted features"** to show exactly what data the model
  is looking at — this is a great "how does the AI actually decide?"
  talking point.
- Mention the printed evaluation metrics from `train_model.py`
  (accuracy, precision, recall, confusion matrix) as the "how do we
  know it works" evidence.

## Limitations (good to mention proactively)

- The model only looks at the **URL text itself**, not the live page
  content, WHOIS data, or SSL certificate — a production system would
  combine several of these signals.
- Training data is **synthetically generated**, not collected from a
  real phishing feed, so it captures common patterns rather than every
  real-world trick.
- This is a prototype for learning/demo purposes, not a production
  security tool.

## Possible extensions

- Add a browser extension that scans links as you hover over them.
- Pull in a real-world labeled dataset (e.g. PhishTank, OpenPhish) for
  training.
- Add a second model for scanning raw email text for phishing language.
- Log every scan to a small database and show a history/dashboard.
