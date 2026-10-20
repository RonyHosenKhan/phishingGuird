"""
PhishGuard AI - Feature Extraction Engine
Extracts 16 handcrafted structural, lexical, and NLP features from URLs and message payloads.
Compliant with PhishGuard AI Project Proposal specifications.
"""

import math
import re
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "work", "click",
    "loan", "cam", "fit", "buzz", "party", "date", "racing", "review",
    "country", "stream", "gdn", "mom", "vip", "icu", "cyou", "monster"
}

SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "verification", "secure", "account", "update",
    "banking", "signin", "sign-in", "password", "paypal", "apple", "google",
    "microsoft", "netflix", "bkash", "nagad", "wallet", "recover", "security",
    "confirm", "support", "billing", "authenticate", "portal", "token"
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "suspended", "suspend", "action required",
    "terminated", "terminate", "24 hours", "24h", "48 hours", "expire",
    "expires", "restricted", "blocked", "warning", "unauthorized", "alert",
    "penalty", "court", "legal action", "final notice", "critical"
]

FINANCIAL_LURE_KEYWORDS = [
    "bank", "bkash", "nagad", "lottery", "winner", "prize", "claim",
    "bdt", "usd", "cash", "refund", "reward", "crypto", "bitcoin",
    "free gift", "congratulations", "bonus", "grant", "transferred", "deposited"
]

CREDENTIAL_HARVEST_KEYWORDS = [
    "pin", "otp", "password", "passcode", "secret code", "credentials",
    "verify pin", "click link", "tap link", "login to continue", "enter pin",
    "reset password", "security question", "card number", "cvv"
]


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string (detects algorithmic random DGA domains)."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def extract_features(text: str = "", url: str = "", app_id: str = "sms") -> dict:
    """
    Extracts 16 numerical features, normalized roughly between 0.0 and 1.0,
    along with human-interpretable feature explanations.
    """
    text = text or ""
    url = url or ""
    
    # If text contains an embedded URL and url field is blank, extract it
    if not url and text:
        found_urls = re.findall(r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)', text)
        if found_urls:
            url = found_urls[0]

    # Normalize URL if needed
    full_url = url
    if full_url and not full_url.startswith(("http://", "https://")):
        full_url = "http://" + full_url

    parsed = urlparse(full_url) if full_url else None
    domain = parsed.netloc if parsed else ""
    path = parsed.path if parsed else ""

    # 1. URL Length
    url_len = len(url)
    f_url_len = min(url_len / 100.0, 1.0)

    # 2. Domain Length
    dom_len = len(domain)
    f_dom_len = min(dom_len / 50.0, 1.0)

    # 3. IP address presence (e.g. http://192.168.1.1/login)
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?$'
    has_ip = 1.0 if re.match(ip_pattern, domain) else 0.0

    # 4. Subdomain Count (e.g., login.account.security.bank.com -> 4)
    subdomains = domain.split(".")
    subdomain_count = max(0, len(subdomains) - 2) if len(subdomains) > 1 else 0
    f_subdomains = min(subdomain_count / 4.0, 1.0)

    # 5. HTTPS presence (Phishing often uses unencrypted HTTP or free certs on strange domains)
    is_https = 1.0 if full_url.startswith("https://") else 0.0

    # 6. Suspicious TLD
    tld = subdomains[-1].lower() if subdomains else ""
    is_suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # 7. Special Character Ratio in URL (@, -, _, ?, =, %, &)
    special_chars = sum(url.count(c) for c in "@-_?=%&~")
    f_special_chars = min(special_chars / 10.0, 1.0)

    # 8. Digit Ratio in URL
    digit_count = sum(c.isdigit() for c in url)
    f_digit_ratio = (digit_count / url_len) if url_len > 0 else 0.0

    # 9. Shannon Entropy of Domain
    entropy = calculate_entropy(domain)
    f_entropy = min(entropy / 5.0, 1.0)

    # 10. Suspicious Keyword Matches in URL
    url_kw_matches = sum(1 for kw in SUSPICIOUS_URL_KEYWORDS if kw in full_url.lower())
    f_url_keywords = min(url_kw_matches / 3.0, 1.0)

    # NLP Message Features
    text_lower = text.lower()

    # 11. Urgency / Panic Score
    urgency_matches = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    f_urgency = min(urgency_matches / 2.0, 1.0)

    # 12. Financial Bait Score
    financial_matches = sum(1 for kw in FINANCIAL_LURE_KEYWORDS if kw in text_lower)
    f_financial = min(financial_matches / 2.0, 1.0)

    # 13. Credential Harvesting / Verification Cues
    cred_matches = sum(1 for kw in CREDENTIAL_HARVEST_KEYWORDS if kw in text_lower)
    f_cred_harvest = min(cred_matches / 2.0, 1.0)

    # 14. Uppercase Ratio (SHOUTING / Urgency)
    caps_count = sum(1 for c in text if c.isupper())
    f_caps_ratio = (caps_count / len(text)) if text else 0.0

    # 15. Exclamation Frequency
    excl_count = text.count("!")
    f_exclamation = min(excl_count / 3.0, 1.0)

    # 16. App Context Risk Multiplier (SMS & WhatsApp deep-links are higher threat vector)
    app_weights = {
        "sms": 0.85,
        "whatsapp": 0.80,
        "messenger": 0.75,
        "email": 0.70,
        "browser": 0.65
    }
    f_app_risk = app_weights.get(app_id.lower(), 0.70)

    feature_vector = [
        f_url_len,
        f_dom_len,
        has_ip,
        f_subdomains,
        1.0 - is_https,  # High risk if NOT https
        is_suspicious_tld,
        f_special_chars,
        f_digit_ratio,
        f_entropy,
        f_url_keywords,
        f_urgency,
        f_financial,
        f_cred_harvest,
        f_caps_ratio,
        f_exclamation,
        f_app_risk
    ]

    feature_names = [
        "URL Length",
        "Domain Length",
        "IP-Based Host",
        "Subdomain Depth",
        "Missing HTTPS",
        "Suspicious TLD",
        "Special Char Density",
        "Digit Ratio",
        "Domain Entropy",
        "URL Phishing Keywords",
        "Urgency & Panic Language",
        "Financial Lure",
        "Credential Harvesting Cues",
        "ALL-CAPS Ratio",
        "Exclamation Frequency",
        "App Attack Vector Risk"
    ]

    explanations = {
        "url_length": f"{url_len} chars",
        "domain": domain or "None",
        "has_ip_host": bool(has_ip),
        "subdomain_count": subdomain_count,
        "is_https": bool(is_https),
        "suspicious_tld": f".{tld}" if is_suspicious_tld else "Standard",
        "special_chars": special_chars,
        "domain_entropy": round(entropy, 3),
        "matched_url_keywords": [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in full_url.lower()],
        "matched_urgency_words": [kw for kw in URGENCY_KEYWORDS if kw in text_lower],
        "matched_financial_words": [kw for kw in FINANCIAL_LURE_KEYWORDS if kw in text_lower],
        "matched_credential_words": [kw for kw in CREDENTIAL_HARVEST_KEYWORDS if kw in text_lower]
    }

    return {
        "vector": feature_vector,
        "feature_names": feature_names,
        "explanations": explanations,
        "extracted_url": full_url if url else None
    }
