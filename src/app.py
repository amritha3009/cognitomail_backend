"""
app.py
------
Flask REST API — CognitoMail backend.

- ML scoring (Random Forest)
- Hybrid hard-rule boosts (fixes auth false-negatives)
- VirusTotal on sender domain + domains found in email links
- Rich feature details for the extension UI

Endpoints:
    POST /analyze
    GET  /health
    GET  /model-info
    POST /feedback

Env (Render):
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
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import extract_features, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

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
            "No trained model at models/phishing_model.pkl. "
            "Run train_model.py first. Using rule-based fallback."
        )


load_model()


# ---------------------------------------------------------------------------
# Domain / VirusTotal helpers
# ---------------------------------------------------------------------------

def get_sender_domain(sender: str) -> str:
    m = re.search(r"@([\w.\-]+)", sender or "")
    return m.group(1).lower() if m else ""


def domains_from_urls(urls: list) -> list:
    found, seen = [], set()
    for raw in urls or []:
        try:
            u = (raw or "").strip()
            if not u:
                continue
            if "://" not in u:
                u = "http://" + u
            host = (urlparse(u).hostname or "").lower().lstrip(".")
            if not host or "." not in host or host in seen:
                continue
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                continue  # skip pure IPs for domain endpoint
            seen.add(host)
            found.append(host)
        except Exception:
            continue
    return found[:5]  # free-tier friendly


def virustotal_domain_report(domain: str) -> dict:
    if not domain:
        return {"available": False, "reason": "no_domain", "domain": domain or ""}
    if not VT_API_KEY:
        return {"available": False, "reason": "no_api_key", "domain": domain}

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=8)

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
        }
    except requests.Timeout:
        return {"available": False, "reason": "timeout", "domain": domain}
    except Exception as e:
        log.warning(f"VirusTotal error for {domain}: {e}")
        return {"available": False, "reason": str(e), "domain": domain}


def virustotal_multi(domains: list) -> dict:
    reports = []
    max_malicious = 0
    max_suspicious = 0
    worst_domain = None

    for d in domains:
        rep = virustotal_domain_report(d)
        reports.append(rep)
        if rep.get("available"):
            m = rep.get("malicious", 0)
            s = rep.get("suspicious", 0)
            if m > max_malicious or (m == max_malicious and s > max_suspicious):
                max_malicious, max_suspicious, worst_domain = m, s, d

    return {
        "available": any(r.get("available") for r in reports),
        "queried": domains,
        "worst_domain": worst_domain,
        "max_malicious": max_malicious,
        "max_suspicious": max_suspicious,
        "reports": reports,
    }


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


# ---------------------------------------------------------------------------
# Hybrid hard rules
# ---------------------------------------------------------------------------

def apply_hard_rules(result: dict, feat_vals: list) -> dict:
    score = int(result.get("risk_score", 0))
    flags = list(result.get("flags") or [])
    boost = 0

    spf_fail = feat_vals[0] == 0
    dkim_fail = feat_vals[1] == 0
    dmarc_fail = feat_vals[2] == 0
    auth_fails = sum([spf_fail, dkim_fail, dmarc_fail])

    if auth_fails >= 3:
        boost += 30
        flags.append("All authentication checks failed (SPF + DKIM + DMARC)")
    elif auth_fails == 2:
        boost += 22
        flags.append("Multiple email authentication failures (SPF/DKIM/DMARC)")
    elif auth_fails == 1:
        boost += 10

    brand = feat_vals[15]
    if brand > 0 and auth_fails >= 1:
        boost += 20
        flags.append("Brand impersonation combined with failed authentication")
    elif brand > 0:
        boost += 8
        flags.append("Brand name impersonation detected")

    if feat_vals[14] > 0:
        boost += 12
        if "Credential-harvesting language detected" not in flags and \
           "Credential-related words detected" not in flags:
            flags.append("Credential-harvesting language detected")

    if feat_vals[8] > 0 or feat_vals[12] > 1:
        boost += 8

    if feat_vals[13] > 0:
        boost += 8

    if feat_vals[21]:
        boost += 15
        if "URL uses IP address" not in " ".join(flags):
            flags.append("URL uses IP address instead of domain name")

    if feat_vals[23] > 0:
        boost += 8
        if "Non-HTTPS" not in " ".join(flags):
            flags.append("Non-HTTPS links present")

    if feat_vals[22] > 0:
        boost += 12
        if "Suspicious top-level domain" not in " ".join(flags):
            flags.append("Suspicious top-level domain in URL")

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

    seen, unique_flags = set(), []
    for f in flags:
        if f not in seen:
            seen.add(f)
            unique_flags.append(f)

    method = result.get("method", "ml")
    if boost > 0 and "+rules" not in method:
        method = f"{method}+rules"

    result.update({
        "risk_score": new_score,
        "verdict": verdict,
        "colour": colour,
        "flags": unique_flags,
        "method": method,
        "rule_boost": boost,
    })
    return result


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def rule_based_score(email: dict) -> dict:
    score, flags = 0, []
    feats = extract_features(email)

    if feats[0] == 0: score += 15; flags.append("SPF check failed or missing")
    if feats[1] == 0: score += 15; flags.append("DKIM check failed or missing")
    if feats[2] == 0: score += 10; flags.append("DMARC check failed or missing")
    if feats[8] > 0:  score += 10; flags.append(f"Urgency words in subject ({int(feats[8])})")
    if feats[12] > 1: score += 10; flags.append(f"Multiple urgency words in body ({int(feats[12])})")
    if feats[14] > 0: score += 15; flags.append("Credential-related words detected")
    if feats[15] > 0: score += 10; flags.append(f"Known brand name in email ({int(feats[15])})")
    if feats[21] == 1: score += 20; flags.append("URL contains an IP address instead of a domain")
    if feats[22] > 0: score += 15; flags.append(f"Suspicious top-level domain ({int(feats[22])})")
    if feats[23] > 0: score += 10; flags.append(f"Non-HTTPS URLs found ({int(feats[23])})")
    if feats[27] > 0: score += 10; flags.append("HTML form elements detected")
    if feats[28] > 0: score += 15; flags.append("Hidden text elements detected")
    if feats[29] > 0: score += 10; flags.append("Redirect links detected")

    score = min(score, 100)
    if score >= 70:   verdict, colour = "Phishing", "red"
    elif score >= 40: verdict, colour = "Suspicious", "orange"
    else:             verdict, colour = "Likely Safe", "green"

    result = {
        "verdict": verdict, "risk_score": score, "colour": colour,
        "flags": flags, "method": "rule-based", "confidence": None,
        "details": build_details(email, feats),
    }
    return apply_hard_rules(result, feats)


def ml_score(email: dict) -> dict:
    feats = np.array([extract_features(email)], dtype=np.float32)
    proba = pipeline.predict_proba(feats)[0]
    phish_prob = float(proba[1])
    risk_score = int(phish_prob * 100)

    if phish_prob >= 0.75:   verdict, colour = "Phishing", "red"
    elif phish_prob >= 0.45: verdict, colour = "Suspicious", "orange"
    else:                    verdict, colour = "Likely Safe", "green"

    feat_vals = feats[0]
    flags = []
    if feat_vals[0] == 0: flags.append("SPF authentication failed")
    if feat_vals[1] == 0: flags.append("DKIM authentication failed")
    if feat_vals[2] == 0: flags.append("DMARC authentication failed")
    if feat_vals[8] > 0:  flags.append("Urgency words in subject")
    if feat_vals[12] > 1: flags.append("Multiple urgency words in body")
    if feat_vals[14] > 0: flags.append("Credential-harvesting language detected")
    if feat_vals[15] > 0: flags.append("Brand name impersonation detected")
    if feat_vals[21]:     flags.append("URL uses IP address instead of domain name")
    if feat_vals[22] > 0: flags.append("Suspicious top-level domain in URL")
    if feat_vals[23] > 0: flags.append("Non-HTTPS links present")
    if feat_vals[28] > 0: flags.append("Hidden content elements in email")
    if feat_vals[29] > 0: flags.append("Redirect links detected")
    if not flags:
        flags.append(
            "No significant phishing signals detected"
            if phish_prob < 0.45
            else "Combination of low-level signals raised suspicion"
        )

    result = {
        "verdict": verdict, "risk_score": risk_score, "colour": colour,
        "flags": flags, "method": "ml", "confidence": round(phish_prob, 4),
        "details": build_details(email, feat_vals.tolist()),
    }
    return apply_hard_rules(result, feat_vals.tolist())


# ---------------------------------------------------------------------------
# Routes
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
        return jsonify({"error": "No model loaded"}), 503
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
        result = ml_score(email_dict) if pipeline is not None else rule_based_score(email_dict)
    except Exception as e:
        log.error(f"Analysis error: {e}")
        return jsonify({"error": "Analysis failed", "detail": str(e)}), 500

    # VirusTotal: sender + link domains
    sender_domain = get_sender_domain(email_dict["sender"])
    link_domains = domains_from_urls(email_dict["urls"])
    domains_to_check = []
    for d in [sender_domain] + link_domains:
        if d and d not in domains_to_check:
            domains_to_check.append(d)

    vt_multi = virustotal_multi(domains_to_check)
    result["sender_domain"] = sender_domain
    result["link_domains"] = link_domains
    result["virustotal"] = vt_multi

    if vt_multi.get("available"):
        mal = vt_multi.get("max_malicious", 0)
        sus = vt_multi.get("max_suspicious", 0)
        worst = vt_multi.get("worst_domain")
        if mal >= 3:
            extra = min(25, mal * 3)
            result["risk_score"] = min(100, result["risk_score"] + extra)
            result["flags"].append(f"VirusTotal: {mal} engines flagged {worst} as malicious")
            result["rule_boost"] = result.get("rule_boost", 0) + extra
        elif sus >= 5:
            result["flags"].append(f"VirusTotal: {sus} engines marked {worst} as suspicious")

        s = result["risk_score"]
        if s >= 70:   result["verdict"], result["colour"] = "Phishing", "red"
        elif s >= 40: result["verdict"], result["colour"] = "Suspicious", "orange"
        else:         result["verdict"], result["colour"] = "Likely Safe", "green"

    log.info(
        f"Analyzed | verdict={result['verdict']} score={result['risk_score']} "
        f"boost={result.get('rule_boost', 0)} method={result['method']} "
        f"domains={domains_to_check}"
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
        return jsonify({"status": "logged", "message": "Thank you."})
    except Exception as e:
        log.error(f"Feedback error: {e}")
        return jsonify({"error": "Failed to log feedback"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(debug=True, host="0.0.0.0", port=port)