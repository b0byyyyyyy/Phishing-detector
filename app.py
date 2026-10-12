"""
app.py

Flask web app for the AI-Powered Phishing URL Detection prototype.
Loads the trained RandomForest model and lets the user paste in a
URL to get an instant verdict with a confidence score and a breakdown
of the suspicious signals found.

Verdicts:
  phishing    - model score >= 50%, or the link is on the public blocklist
  caution     - model score between 35% and 50% ("be careful")
  legitimate  - model score below 35%, or the domain is a top popular site

Optional data files (the app still works if they are missing):
  data/tranco_top10k.txt  - one popular domain per line
  data/blocklist.txt      - one known malicious URL per line
Nothing the user types is stored or logged by this code.
"""

import os
import re
from urllib.parse import urlparse

import joblib
import pandas as pd
from flask import Flask, jsonify, render_template, request

from feature_extractor import FEATURE_NAMES, extract_features

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_url_model.joblib")
model = joblib.load(MODEL_PATH)

PHISH_THRESHOLD = 0.50    # at or above: likely phishing
CAUTION_THRESHOLD = 0.35  # at or above (and below 0.50): be careful

# Human-friendly explanations for each feature, shown when it's flagged
FEATURE_EXPLANATIONS = {
    "has_ip": "Uses a raw IP address instead of a domain name",
    "has_at_symbol": "Contains an '@' symbol, which can hide the real destination",
    "is_shortened": "Uses a URL-shortening service, hiding the real destination",
    "has_suspicious_word": "Contains words commonly used in phishing (e.g. 'verify', 'login')",
    "tld_suspicious": "Uses a domain ending often associated with cheap/spam domains",
    "https_in_hostname_trick": "Has 'https' embedded in the hostname to look secure",
    "has_double_slash_redirect": "Has a suspicious '//' redirect pattern in the path",
}


def _normalize(url):
    """Lower-case, drop the scheme, a leading www. and a trailing slash."""
    u = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url.strip().lower())
    if u.startswith("www."):
        u = u[4:]
    return u.rstrip("/")


def _load_set(filename):
    path = os.path.join(BASE_DIR, "data", filename)
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        return {_normalize(line) for line in f if line.strip()}


POPULAR_DOMAINS = _load_set("tranco_top10k.txt")
BLOCKLIST = _load_set("blocklist.txt")


def _hostname(url):
    try:
        s = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "https://" + url
        host = (urlparse(s).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def build_feature_row(url):
    feats = extract_features(url)
    df = pd.DataFrame([feats], columns=FEATURE_NAMES)
    return feats, df


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def check_url():
    data = request.get_json(force=True)
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    feats, X = build_feature_row(url)
    model_p = float(model.predict_proba(X)[0][1])  # P(phishing)

    reasons = []
    for key, explanation in FEATURE_EXPLANATIONS.items():
        if feats.get(key, 0) == 1:
            reasons.append(explanation)
    if feats.get("num_hyphens", 0) >= 3:
        reasons.append("Unusually many hyphens in the domain")
    if feats.get("url_length", 0) > 75:
        reasons.append("Unusually long URL")
    if feats.get("num_subdomains", 0) >= 3:
        reasons.append("Unusually many subdomains")

    p = model_p
    if _normalize(url) in BLOCKLIST:
        p = 0.999
        reasons.insert(0, "Listed on a public blocklist of known malicious links")
    elif _hostname(url) in POPULAR_DOMAINS:
        p = min(model_p, 0.05)
        note = "Domain is among the 10,000 most visited websites"
        if model_p >= CAUTION_THRESHOLD:
            note += f" (the AI model alone scored it {model_p * 100:.0f}% phishing)"
        reasons.insert(0, note)

    if p >= PHISH_THRESHOLD:
        verdict = "phishing"
    elif p >= CAUTION_THRESHOLD:
        verdict = "caution"
        reasons.insert(0, "Borderline score: not clearly safe, so treat this link with care")
    else:
        verdict = "legitimate"

    result = {
        "url": url,
        "prediction": verdict,
        "phishing_probability": round(p * 100, 2),
        "legitimate_probability": round((1 - p) * 100, 2),
        "model_probability": round(model_p * 100, 2),
        "reasons": reasons if reasons else ["No strongly suspicious signals detected"],
        "features": feats,
    }
    return jsonify(result)


if __name__ == "__main__":
    # Local development only. On Render, gunicorn runs the app instead
    # (start command: gunicorn app:app), so this block is never used there.
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
