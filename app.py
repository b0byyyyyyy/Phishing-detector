"""
app.py

Flask web app for the AI-Powered Phishing URL Detection prototype.
Loads the trained RandomForest model and lets the user paste in a
URL to get an instant phishing/legitimate prediction with a
confidence score and a breakdown of the suspicious signals found.
"""

from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd

from feature_extractor import extract_features, FEATURE_NAMES

app = Flask(__name__)

MODEL_PATH = "models/phishing_url_model.joblib"
model = joblib.load(MODEL_PATH)

# Human-friendly explanations for each feature, shown when it's flagged
FEATURE_EXPLANATIONS = {
    "has_ip": "Uses a raw IP address instead of a domain name",
    "has_at_symbol": "Contains an '@' symbol, which can hide the real destination",
    "is_shortened": "Uses a URL-shortening service, hiding the real destination",
    "has_suspicious_word": "Contains words commonly used in phishing (e.g. 'verify', 'login')",
    "tld_suspicious": "Uses a domain ending often associated with cheap/spam domains",
    "https_in_hostname_trick": "Has 'https' embedded in the hostname to look secure",
    "has_double_slash_redirect": "Has a suspicious '//' redirect pattern in the path",
    "has_ip_ish_subdomain": "Suspicious subdomain structure",
}


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
    proba = model.predict_proba(X)[0]  # [P(legit), P(phishing)]
    pred = int(model.predict(X)[0])

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

    result = {
        "url": url,
        "prediction": "phishing" if pred == 1 else "legitimate",
        "phishing_probability": round(float(proba[1]) * 100, 2),
        "legitimate_probability": round(float(proba[0]) * 100, 2),
        "reasons": reasons if reasons else ["No strongly suspicious signals detected"],
        "features": feats,
    }
    return jsonify(result)


if __name__ == "__main__":
    # Local development only. On Render, gunicorn runs the app instead
    # (see Procfile / start command: gunicorn app:app), so this block
    # is never used in production.
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
