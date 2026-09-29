"""
feature_extractor.py
Extracts lexical/structural features from a URL that are commonly
used to distinguish phishing URLs from legitimate ones.

No network calls are made — everything is derived purely from the
URL string, so this works instantly and offline.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "update", "secure", "banking",
    "confirm", "signin", "webscr", "password", "pay", "suspend",
    "urgent", "alert", "limited", "click", "免费", "free", "bonus"
]

SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "rb.gy"
]

IP_PATTERN = re.compile(
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)


def extract_features(url: str) -> dict:
    """Return a dict of numeric/binary features for a given URL."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        # Assume http if no scheme given, so urlparse works correctly
        parsed_url_for_parts = "http://" + url
    else:
        parsed_url_for_parts = url

    parsed = urlparse(parsed_url_for_parts)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()

    features = {}

    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["has_ip"] = 1 if IP_PATTERN.search(hostname) else 0
    features["has_at_symbol"] = 1 if "@" in url else 0
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_underscores"] = url.count("_")
    features["num_slashes"] = url.count("/")
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["num_subdomains"] = max(hostname.count(".") - 1, 0)
    features["has_https"] = 1 if parsed.scheme == "https" else 0
    features["https_in_hostname_trick"] = 1 if "https" in hostname.lower() else 0
    features["is_shortened"] = 1 if any(s in hostname for s in SHORTENING_SERVICES) else 0
    features["has_suspicious_word"] = 1 if any(w in full for w in SUSPICIOUS_WORDS) else 0
    features["num_suspicious_words"] = sum(1 for w in SUSPICIOUS_WORDS if w in full)
    features["path_length"] = len(path)
    features["has_double_slash_redirect"] = 1 if "//" in path else 0
    features["count_query_params"] = url.count("=")
    features["has_port"] = 1 if parsed.port else 0
    features["tld_suspicious"] = 1 if hostname.split(".")[-1] in [
        "xyz", "top", "club", "gq", "tk", "ml", "cf", "work", "info"
    ] else 0

    return features


FEATURE_NAMES = list(extract_features("http://example.com").keys())


if __name__ == "__main__":
    test_urls = [
        "http://192.168.1.1/login/verify-account",
        "https://www.google.com",
        "http://secure-paypal-login.tk/confirm?user=1&pass=2",
    ]
    for u in test_urls:
        print(u, "->", extract_features(u))
