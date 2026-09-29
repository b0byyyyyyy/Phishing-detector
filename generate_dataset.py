"""
generate_dataset.py

Builds a labeled dataset of URLs (phishing = 1, legitimate = 0) using
realistic templates + randomized variation. This keeps the project
fully offline/self-contained (no dataset download needed) while still
producing believable, varied examples for training and demoing.
"""

import random
import csv

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "amazon.com", "microsoft.com",
    "apple.com", "netflix.com", "linkedin.com", "yahoo.com", "reddit.com",
    "nytimes.com", "bbc.com", "spotify.com", "dropbox.com", "adobe.com",
    "stackoverflow.com", "khanacademy.org", "coursera.org", "mit.edu", "who.int",
    "irctc.co.in", "sbi.co.in", "hdfcbank.com", "flipkart.com", "myntra.com",
]

LEGIT_PATHS = [
    "", "/", "/home", "/about", "/products", "/blog/2024/updates",
    "/user/settings", "/help/faq", "/search?q=weather", "/en/index.html",
    "/docs/getting-started", "/watch?v=abc123", "/news/world",
    "/login", "/account", "/signin", "/account/update-details",
]

PHISHING_BRANDS = [
    "paypal", "paypa1", "amazon", "netflix", "apple", "microsoft", "google",
    "hdfcbank", "sbi", "icici", "irctc", "facebook", "instagram", "whatsapp",
    "bankofamerica", "chase", "wellsfargo", "flipkart", "gov-refund", "dhl", "fedex",
]

PHISHING_SUFFIXES = [
    "-login", "-verify", "-secure", "-update", "-account", "-alert",
    "-confirm", "-support", "-billing", "-signin",
]

SUSPICIOUS_TLDS = ["tk", "ml", "cf", "gq", "xyz", "top", "club", "work", "info", "gq"]

PHISHING_PATHS = [
    "/login", "/verify-account", "/secure/update.php", "/confirm?user=1&pass=2",
    "/index.html?redirect=paypal.com", "/account/suspended", "/billing/invoice.php",
    "/reset-password", "/claim-reward", "/track-package?id=", "/win-prize.html",
]

SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "rb.gy"]


def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))


def make_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https"
    sub = random.choice(["", "www.", "www.", "www.", "m.", "mail."])
    return f"{scheme}://{sub}{domain}{path}"


def make_phishing_url():
    style = random.choice(["ip", "subdomain_trick", "typo_tld", "shortener", "long_random"])
    brand = random.choice(PHISHING_BRANDS)
    suffix = random.choice(PHISHING_SUFFIXES)
    path = random.choice(PHISHING_PATHS)
    scheme = random.choice(["http", "http", "https"])

    if style == "ip":
        return f"{scheme}://{random_ip()}{path}"
    elif style == "subdomain_trick":
        # e.g. paypal.com.verify-secure.tk
        real_brand_domain = random.choice(["paypal.com", "amazon.com", "apple.com", "hdfcbank.com"])
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"{scheme}://{real_brand_domain}.{brand}{suffix}.{tld}{path}"
    elif style == "typo_tld":
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"{scheme}://{brand}{suffix}.{tld}{path}"
    elif style == "shortener":
        shortener = random.choice(SHORTENERS)
        code = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=7))
        return f"{scheme}://{shortener}/{code}"
    else:  # long_random
        tld = random.choice(SUSPICIOUS_TLDS + ["com", "net"])
        junk = "".join(random.choices("abcdefghijklmnopqrstuvwxyz-", k=random.randint(15, 30))).strip("-")
        return f"{scheme}://{brand}{suffix}-{junk}.{tld}{path}"


def make_tricky_legit_url():
    """Legit-looking URLs that use hyphens/numbers/subdomains, so the
    model can't rely purely on 'has a hyphen' style shortcuts."""
    domain = random.choice(LEGIT_DOMAINS)
    sub = random.choice(["news-", "shop-", "api-", "cdn1-", "static-", "my-"])
    path = random.choice(LEGIT_PATHS)
    return f"https://{sub}{domain}{path}"


def make_tricky_phishing_url():
    """Phishing URLs that use https, a clean-ish looking domain, and a
    plain/benign-sounding path, relying mostly on the brand+suffix
    domain trick rather than obvious 'verify/login' keywords."""
    brand = random.choice(PHISHING_BRANDS)
    suffix = random.choice(PHISHING_SUFFIXES)
    path = random.choice(["", "/", "/home", "/index.html", "/dashboard"])
    return f"https://{brand}{suffix}.com{path}"


def build_dataset(n_per_class=500, tricky_fraction=0.12):
    rows = []
    n_tricky = int(n_per_class * tricky_fraction)
    n_normal = n_per_class - n_tricky

    for _ in range(n_normal):
        rows.append((make_legit_url(), 0))
    for _ in range(n_tricky):
        rows.append((make_tricky_legit_url(), 0))

    for _ in range(n_normal):
        rows.append((make_phishing_url(), 1))
    for _ in range(n_tricky):
        rows.append((make_tricky_phishing_url(), 1))

    random.shuffle(rows)
    return rows


if __name__ == "__main__":
    rows = build_dataset(n_per_class=600)
    with open("data/urls.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to data/urls.csv")
