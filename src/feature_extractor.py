"""
feature_extractor.py
--------------------
Extracts numerical features from an email dict for ML classification.

Input format (from browser extension DOM extraction):
{
    "sender":  "someone@example.com",
    "subject": "Urgent: Verify your account",
    "body":    "Dear user, click here to verify...",
    "urls":    ["http://evil.ru/login", ...],
    "spf":     "pass" | "fail" | "none",
    "dkim":    "pass" | "fail" | "none",
    "dmarc":   "pass" | "fail" | "none"
}

Output: a flat list of 30 numeric features (same order every time).
"""

import re
import math
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Phishing signal word lists
# ---------------------------------------------------------------------------

URGENCY_WORDS = [
    "urgent", "immediately", "alert", "warning", "suspended", "verify",
    "validate", "confirm", "unusual", "limited time", "expires", "deadline",
    "act now", "account locked", "blocked", "compromise", "breach"
]

REWARD_WORDS = [
    "winner", "won", "prize", "reward", "congratulations", "free", "gift",
    "lottery", "selected", "claim", "bonus", "offer", "exclusive"
]

CREDENTIAL_WORDS = [
    "password", "username", "login", "sign in", "credit card", "ssn",
    "social security", "bank account", "pin", "otp", "verification code",
    "billing", "payment", "invoice"
]

KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook", "netflix",
    "instagram", "twitter", "linkedin", "dropbox", "chase", "wells fargo",
    "bank of america", "citibank", "dhl", "fedex", "ups", "usps"
]

SUSPICIOUS_TLDS = [
    ".ru", ".cn", ".tk", ".pw", ".cc", ".xyz", ".top", ".work",
    ".click", ".link", ".gq", ".cf", ".ml", ".ga"
]

FREE_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "icloud.com", "mail.com",
    "yandex.com", "gmx.com"
]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _entropy(s: str) -> float:
    """Shannon entropy of a string — high entropy = random-looking domain."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _count_words(text: str, word_list: list) -> int:
    text_lower = text.lower()
    return sum(1 for w in word_list if w in text_lower)


def _extract_domain(email_addr: str) -> str:
    """Pull domain from an email address string."""
    match = re.search(r"@([\w.\-]+)", email_addr)
    return match.group(1).lower() if match else ""


def _auth_score(val: str) -> int:
    """Convert SPF/DKIM/DMARC string to 0 (fail/none) or 1 (pass)."""
    return 1 if str(val).lower() == "pass" else 0


# ---------------------------------------------------------------------------
# Per-URL features (averaged across all URLs in the email)
# ---------------------------------------------------------------------------

def _url_features(urls: list) -> dict:
    if not urls:
        return {
            "url_count": 0,
            "avg_url_length": 0,
            "avg_url_entropy": 0,
            "has_ip_url": 0,
            "suspicious_tld_count": 0,
            "http_count": 0,
            "url_domain_mismatch": 0,
            "subdomain_count": 0,
            "special_char_ratio": 0,
        }

    lengths, entropies, subdomains, special_chars = [], [], [], []
    has_ip, sus_tld, http_count, mismatches = 0, 0, 0, 0

    domains_seen = set()

    for raw_url in urls:
        url = raw_url.strip()
        try:
            parsed = urlparse(url if "://" in url else "http://" + url)
            host = parsed.hostname or ""
        except Exception:
            host = ""

        lengths.append(len(url))
        entropies.append(_entropy(host))
        subdomains.append(max(0, host.count(".") - 1))

        # Special chars in path/query
        path = parsed.path + (parsed.query or "")
        total = len(path) if path else 1
        sc = sum(path.count(c) for c in ["@", "//", "%", "~", "=", "&"])
        special_chars.append(sc / total)

        # IP-based URL
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            has_ip = 1

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                sus_tld += 1
                break

        # HTTP (not HTTPS)
        if parsed.scheme == "http":
            http_count += 1

        domains_seen.add(host)

    return {
        "url_count": len(urls),
        "avg_url_length": sum(lengths) / len(lengths),
        "avg_url_entropy": sum(entropies) / len(entropies),
        "has_ip_url": has_ip,
        "suspicious_tld_count": sus_tld,
        "http_count": http_count,
        "url_domain_mismatch": len(domains_seen),   # many different domains = suspicious
        "subdomain_count": sum(subdomains) / len(subdomains),
        "special_char_ratio": sum(special_chars) / len(special_chars),
    }


# ---------------------------------------------------------------------------
# Main extraction function
# ---------------------------------------------------------------------------

def extract_features(email: dict) -> list:
    """
    Returns a list of 30 floats representing one email.
    ORDER MUST NEVER CHANGE after the model is trained.
    """

    sender  = str(email.get("sender",  ""))
    subject = str(email.get("subject", ""))
    body    = str(email.get("body",    ""))
    urls    = email.get("urls", [])
    spf     = email.get("spf",   "none")
    dkim    = email.get("dkim",  "none")
    dmarc   = email.get("dmarc", "none")

    full_text = subject + " " + body
    sender_domain = _extract_domain(sender)
    url_feats = _url_features(urls)

    # ---- Authentication (3) ------------------------------------------------
    f_spf   = _auth_score(spf)
    f_dkim  = _auth_score(dkim)
    f_dmarc = _auth_score(dmarc)

    # ---- Sender (4) ---------------------------------------------------------
    f_free_email      = 1 if sender_domain in FREE_EMAIL_DOMAINS else 0
    f_sender_entropy  = _entropy(sender_domain)
    f_sender_digits   = sum(c.isdigit() for c in sender_domain) / max(len(sender_domain), 1)
    f_display_mismatch = 1 if (
        re.search(r"<(.+?)>", sender) and
        sender.split("<")[0].strip().lower() not in sender_domain
    ) else 0

    # ---- Subject (4) --------------------------------------------------------
    f_subject_len          = len(subject)
    f_subject_urgency      = _count_words(subject, URGENCY_WORDS)
    f_subject_all_caps     = sum(1 for w in subject.split() if w.isupper() and len(w) > 2)
    f_subject_exclamations = subject.count("!")

    # ---- Body text (7) ------------------------------------------------------
    words = full_text.split()
    f_body_len          = len(body)
    f_urgency_count     = _count_words(full_text, URGENCY_WORDS)
    f_reward_count      = _count_words(full_text, REWARD_WORDS)
    f_credential_count  = _count_words(full_text, CREDENTIAL_WORDS)
    f_brand_impersonation = _count_words(full_text, KNOWN_BRANDS)
    f_caps_ratio        = sum(1 for w in words if w.isupper()) / max(len(words), 1)
    f_body_entropy      = _entropy(body[:500])   # first 500 chars is enough

    # ---- URL features (9) — from _url_features() ---------------------------
    f_url_count          = url_feats["url_count"]
    f_avg_url_len        = url_feats["avg_url_length"]
    f_avg_url_entropy    = url_feats["avg_url_entropy"]
    f_has_ip_url         = url_feats["has_ip_url"]
    f_suspicious_tld     = url_feats["suspicious_tld_count"]
    f_http_count         = url_feats["http_count"]
    f_url_domain_variety = url_feats["url_domain_mismatch"]
    f_subdomain_depth    = url_feats["subdomain_count"]
    f_special_char_ratio = url_feats["special_char_ratio"]

    # ---- Structural signals (3) ---------------------------------------------
    f_html_forms    = len(re.findall(r"<form|<input", body, re.IGNORECASE))
    f_hidden_text   = len(re.findall(r'style\s*=\s*["\'].*?display\s*:\s*none', body, re.IGNORECASE))
    f_redirect_links = len(re.findall(r"redirect|url=http|forward=http", body, re.IGNORECASE))

    # ---- Assemble in fixed order (30 total) ---------------------------------
    features = [
        # Auth (3)
        f_spf, f_dkim, f_dmarc,
        # Sender (4)
        f_free_email, f_sender_entropy, f_sender_digits, f_display_mismatch,
        # Subject (4)
        f_subject_len, f_subject_urgency, f_subject_all_caps, f_subject_exclamations,
        # Body (7)
        f_body_len, f_urgency_count, f_reward_count, f_credential_count,
        f_brand_impersonation, f_caps_ratio, f_body_entropy,
        # URLs (9)
        f_url_count, f_avg_url_len, f_avg_url_entropy, f_has_ip_url,
        f_suspicious_tld, f_http_count, f_url_domain_variety,
        f_subdomain_depth, f_special_char_ratio,
        # Structural (3)
        f_html_forms, f_hidden_text, f_redirect_links,
    ]

    return [float(x) for x in features]


FEATURE_NAMES = [
    "spf_pass", "dkim_pass", "dmarc_pass",
    "free_email_domain", "sender_entropy", "sender_digits_ratio", "display_name_mismatch",
    "subject_length", "subject_urgency_words", "subject_all_caps_words", "subject_exclamations",
    "body_length", "urgency_word_count", "reward_word_count", "credential_word_count",
    "brand_impersonation_count", "caps_word_ratio", "body_entropy",
    "url_count", "avg_url_length", "avg_url_entropy", "has_ip_based_url",
    "suspicious_tld_count", "http_url_count", "url_domain_variety",
    "avg_subdomain_depth", "special_char_ratio_in_urls",
    "html_form_elements", "hidden_text_elements", "redirect_link_count",
]
