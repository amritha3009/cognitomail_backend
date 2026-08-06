"""
app.py
------
Flask REST API — bridge between the browser extension and the ML model.

Endpoints:
    POST /analyze
    GET  /health
    GET  /model-info
    POST /feedback

Environment variables (Render):
    VT_API_KEY
    PORT
"""

import os
import sys
import re
import logging
import joblib
import numpy as np
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import extract_features, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH = os.path.join(MODELS_DIR, "phishing_model.pkl")

pipeline = None


def load_model():
    global pipeline
    if os.path.exists(MODEL_PATH):
        pipeline = joblib.load(MODEL_PATH)
        log.info(f"Model loaded from {MODEL_PATH}")
    else:
        log.warning(
            "No trained model found at models/phishing_model.pkl. "
            "Run 'python src/train_model.py' first. "
            "API will use rule-based fallback until model is ready."
        )


load_model()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_sender_domain(sender: str) -> str:
    m = re.search(r"@([\w.\-]+)", sender or "")
    return m.group(1).lower() if m else ""


def virustotal_domain_report(domain: str) -> dict:
    if not domain:
        return {"available": False, "reason": "no_domain"}
    if not VT_API_KEY:
        return {"available": False, "reason": "no_api_key"}

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(url, headers=headers, timeout=8)

        if r.status_code == 404:
            return {"available": False, "reason": "domain_not_found", "domain": domain}
        if r.status_code == 429:
            return {"available": False, "reason": "rate_limited", "domain": domain}
        if r.status_code != 200:
            return {"available": False, "reason": f"http_{r.status_code}", "domain": domain}

        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected or 1

        return {
            "available": True,
            "domain": domain,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "malicious_ratio": round(malicious / total, 3),
            "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}) or {},
            "last_analysis_date": attrs.get("last_analysis_date"),
        }
    except requests.Timeout:
        return {"available": False, "reason": "timeout", "domain": domain}
    except Exception as e:
        log.warning(f"VirusTotal error for {domain}: {e}")
        return {"available": False, "reason": str(e), "domain": domain}


def build_details(email: dict, feat_vals: list) -> dict:
    return {
        "sender_domain": get_sender_domain(email.get("sender", "")),
        "free_email_domain": bool(feat_vals[3]),
        "subject_length": int(feat_vals[7]),
        "subject_urgency_words": int(feat_vals[8]),
        "subject_all_caps_words": int(feat_vals[9]),
        "subject_exclamations": int(feat_vals[10]),
        "body_length": int(feat_vals[11]),
        "urgency_word_count": int(feat_vals[12]),
        "reward_word_count": int(feat_vals[13]),
        "credential_word_count": int(feat_vals[14]),
        "brand_impersonation_count": int(feat_vals[15]),
        "url_count": int(feat_vals[18]),
        "has_ip_based_url": bool(feat_vals[21]),
        "suspicious_tld_count": int(feat_vals[22]),
        "http_url_count": int(feat_vals[23]),
        "url_domain_variety": int(feat_vals[24]),
        "html_form_elements": int(feat_vals[27]),
        "hidden_text_elements": int(feat_vals[28]),
        "redirect_link_count": int(feat_vals[29]),
    }


def apply_hard_rules(result: dict, feat_vals: list) -> dict:
    """
    Hybrid post-processing: boost ML/rule score when high-confidence
    phishing signals are present. Fixes false negatives where the
    Random Forest under-weights SPF/DKIM/DMARC (importance ≈ 0 in training).
    """
    score = int(result.get("risk_score", 0))
    flags = list(result.get("flags") or [])
    boost = 0

    spf_fail = feat_vals[0] == 0
    dkim_fail = feat_vals[1] == 0
    dmarc_fail = feat_vals[2] == 0
    auth_fails = sum([spf_fail, dkim_fail, dmarc_fail])

    # Multiple authentication failures
    if auth_fails >= 3:
        boost += 30
        flags.append("All authentication checks failed (SPF + DKIM + DMARC)")
    elif auth_fails == 2:
        boost += 22
        flags.append("Multiple email authentication failures (SPF/DKIM/DMARC)")
    elif auth_fails == 1:
        boost += 10

    # Brand impersonation + any auth failure (classic phishing)
    brand = feat_vals[15]
    if brand > 0 and auth_fails >= 1:
        boost += 20
        flags.append("Brand impersonation combined with failed authentication")
    elif brand > 0:
        boost += 8
        flags.append("Brand name impersonation detected")

    # Credential-harvesting language
    if feat_vals[14] > 0:
        boost += 12
        if "Credential-harvesting language detected" not in flags and \
           "Credential-related words detected" not in flags:
            flags.append("Credential-harvesting language detected")

    # Urgency
    if feat_vals[8] > 0 or feat_vals[12] > 1:
        boost += 8
        if "Urgency words in subject" not in " ".join(flags) and \
           "Multiple urgency words in body" not in " ".join(flags):
            flags.append("Urgency language detected")

    # Reward / lottery language
    if feat_vals[13] > 0:
        boost += 8

    # IP-based URL
    if feat_vals[21]:
        boost += 15
        if "URL uses IP address instead of domain name" not in flags and \
           "URL contains an IP address instead of a domain" not in flags:
            flags.append("URL uses IP address instead of domain name")

    # Non-HTTPS links
    if feat_vals[23] > 0:
        boost += 8
        if "Non-HTTPS links present" not in flags and \
           "Non-HTTPS URLs found" not in " ".join(flags):
            flags.append("Non-HTTPS links present")

    # Suspicious TLD
    if feat_vals[22] > 0:
        boost += 12
        if "Suspicious top-level domain" not in " ".join(flags):
            flags.append("Suspicious top-level domain in URL")

    # Hidden content / forms / redirects
    if feat_vals[28] > 0:
        boost += 10
    if feat_vals[27] > 0:
        boost += 8
    if feat_vals[29] > 0:
        boost += 8

    new_score = min(100, score + boost)

    if new_score >= 70:
        verdict, colour = "Phishing", "red"
    elif new_score >= 40:
        verdict, colour = "Suspicious", "orange"
    else:
        verdict, colour = "Likely Safe", "green"

    # Deduplicate flags
    seen = set()
    unique_flags = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            unique_flags.append(f)

    method = result.get("method", "ml")
    if boost > 0 and "+rules" not in method:
        method = f"{method}+rules"

    result["risk_score"] = new_score
    result["verdict"] = verdict
    result["colour"] = colour
    result["flags"] = unique_flags
    result["method"] = method
    result["rule_boost"] = boost
    return result


# ---------------------------------------------------------------------------
# Rule-based fallback
# ---------------------------------------------------------------------------

def rule_based_score(email: dict) -> dict:
    score = 0
    flags = []
    feats = extract_features(email)

    if feats[0] == 0:
        score += 15
        flags.append("SPF check failed or missing")
    if feats[1] == 0:
        score += 15
        flags.append("DKIM check failed or missing")
    if feats[2] == 0:
        score += 10
        flags.append("DMARC check failed or missing")
    if feats[8] > 0:
        score += 10
        flags.append(f"Urgency words in subject ({int(feats[8])})")
    if feats[12] > 1:
        score += 10
        flags.append(f"Multiple urgency words in body ({int(feats[12])})")
    if feats[14] > 0:
        score += 15
        flags.append("Credential-related words detected")
    if feats[15] > 0:
        score += 10
        flags.append(f"Known brand name in email ({int(feats[15])})")
    if feats[21] == 1:
        score += 20
        flags.append("URL contains an IP address instead of a domain")
    if feats[22] > 0:
        score += 15
        flags.append(f"Suspicious top-level domain ({int(feats[22])})")
    if feats[23] > 0:
        score += 10
        flags.append(f"Non-HTTPS URLs found ({int(feats[23])})")
    if feats[27] > 0:
        score += 10
        flags.append("HTML form elements detected")
    if feats[28] > 0:
        score += 15
        flags.append("Hidden text elements detected")
    if feats[29] > 0:
        score += 10
        flags.append("Redirect links detected")

    score = min(score, 100)

    if score >= 70:
        verdict, colour = "Phishing", "red"
    elif score >= 40:
        verdict, colour = "Suspicious", "orange"
    else:
        verdict, colour = "Likely Safe", "green"

    result = {
        "verdict": verdict,
        "risk_score": score,
        "colour": colour,
        "flags": flags,
        "method": "rule-based",
        "confidence": None,
        "details": build_details(email, feats),
    }
    return apply_hard_rules(result, feats)


# ---------------------------------------------------------------------------
# ML-based analysis
# ---------------------------------------------------------------------------

def ml_score(email: dict) -> dict:
    feats = np.array([extract_features(email)], dtype=np.float32)
    proba = pipeline.predict_proba(feats)[0]
    phish_prob = float(proba[1])
    risk_score = int(phish_prob * 100)

    if phish_prob >= 0.75:
        verdict, colour = "Phishing", "red"
    elif phish_prob >= 0.45:
        verdict, colour = "Suspicious", "orange"
    else:
        verdict, colour = "Likely Safe", "green"

    feat_vals = feats[0]
    flags = []

    if feat_vals[0] == 0:
        flags.append("SPF authentication failed")
    if feat_vals[1] == 0:
        flags.append("DKIM authentication failed")
    if feat_vals[2] == 0:
        flags.append("DMARC authentication failed")
    if feat_vals[8] > 0:
        flags.append("Urgency words in subject")
    if feat_vals[12] > 1:
        flags.append("Multiple urgency words in body")
    if feat_vals[14] > 0:
        flags.append("Credential-harvesting language detected")
    if feat_vals[15] > 0:
        flags.append("Brand name impersonation detected")
    if feat_vals[21]:
        flags.append("URL uses IP address instead of domain name")
    if feat_vals[22] > 0:
        flags.append("Suspicious top-level domain in URL")
    if feat_vals[23] > 0:
        flags.append("Non-HTTPS links present")
    if feat_vals[28] > 0:
        flags.append("Hidden content elements in email")
    if feat_vals[29] > 0:
        flags.append("Redirect links detected")

    if not flags:
        if phish_prob < 0.45:
            flags.append("No significant phishing signals detected")
        else:
            flags.append("Combination of low-level signals raised suspicion")

    result = {
        "verdict": verdict,
        "risk_score": risk_score,
        "colour": colour,
        "flags": flags,
        "method": "ml",
        "confidence": round(phish_prob, 4),
        "details": build_details(email, feat_vals.tolist()),
    }
    return apply_hard_rules(result, feat_vals.tolist())


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": pipeline is not None,
        "virustotal_configured": bool(VT_API_KEY),
    })


@app.route("/model-info", methods=["GET"])
def model_info():
    if pipeline is None:
        return jsonify({"error": "No model loaded. Run train_model.py first."}), 503

    clf = pipeline.named_steps["clf"]
    return jsonify({
        "model_type": type(clf).__name__,
        "feature_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    email_dict = {
        "sender":  str(data.get("sender", "")),
        "subject": str(data.get("subject", "")),
        "body":    str(data.get("body", "")),
        "urls":    data.get("urls", []),
        "spf":     str(data.get("spf", "none")),
        "dkim":    str(data.get("dkim", "none")),
        "dmarc":   str(data.get("dmarc", "none")),
    }
    if not isinstance(email_dict["urls"], list):
        email_dict["urls"] = []

    try:
        if pipeline is not None:
            result = ml_score(email_dict)
        else:
            result = rule_based_score(email_dict)
    except Exception as e:
        log.error(f"Analysis error: {e}")
        return jsonify({"error": "Analysis failed", "detail": str(e)}), 500

    # VirusTotal domain lookup
    domain = get_sender_domain(email_dict["sender"])
    vt = virustotal_domain_report(domain)
    result["sender_domain"] = domain
    result["virustotal"] = vt

    # Extra boost from VirusTotal
    if vt.get("available") and vt.get("malicious", 0) >= 3:
        extra = min(20, vt["malicious"] * 3)
        result["risk_score"] = min(100, result["risk_score"] + extra)
        result["flags"].append(
            f"VirusTotal: {vt['malicious']} engines flagged domain as malicious"
        )
        result["rule_boost"] = result.get("rule_boost", 0) + extra
        s = result["risk_score"]
        if s >= 70:
            result["verdict"], result["colour"] = "Phishing", "red"
        elif s >= 40:
            result["verdict"], result["colour"] = "Suspicious", "orange"
        else:
            result["verdict"], result["colour"] = "Likely Safe", "green"
    elif vt.get("available") and vt.get("suspicious", 0) >= 5:
        result["flags"].append(
            f"VirusTotal: {vt['suspicious']} engines marked domain as suspicious"
        )

    log.info(
        f"Analyzed | verdict={result['verdict']} score={result['risk_score']} "
        f"boost={result.get('rule_boost', 0)} method={result['method']} "
        f"domain={domain} vt={vt.get('available')}"
    )
    return jsonify(result)


@app.route("/feedback", methods=["POST"])
def feedback():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    email_dict = data.get("email", {})
    predicted_label = int(data.get("predicted_label", -1))
    correct_label = int(data.get("correct_label", -1))

    if predicted_label not in (0, 1) or correct_label not in (0, 1):
        return jsonify({"error": "predicted_label and correct_label must be 0 or 1"}), 400

    try:
        from train_model import log_feedback
        log_feedback(email_dict, predicted_label, correct_label)
        log.info(f"Feedback logged: predicted={predicted_label} correct={correct_label}")
        return jsonify({
            "status": "logged",
            "message": "Thank you — this will improve future detection.",
        })
    except Exception as e:
        log.error(f"Feedback logging error: {e}")
        return jsonify({"error": "Failed to log feedback"}), 500


# ---------------------------------------------------------------------------
# Dev server
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(debug=True, host="0.0.0.0", port=port)