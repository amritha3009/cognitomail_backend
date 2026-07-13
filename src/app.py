"""
app.py
------
Flask REST API — the bridge between the browser extension and the ML model.

Endpoints:
    POST /analyze        ← extension sends email data, gets back a verdict
    GET  /health         ← health check
    GET  /model-info     ← metadata about the loaded model

Run locally:
    cd cognitomail_backend
    python src/app.py

Deploy (Render free tier):
    Set start command to: gunicorn src.app:app
"""

import os
import sys
import logging
import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import extract_features, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

# Allow requests from your Gmail simulation origin
# In production replace "*" with your actual simulation URL
CORS(app, resources={r"/*": {"origins": "*"}})


# ---------------------------------------------------------------------------
# Load model at startup
# ---------------------------------------------------------------------------

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH  = os.path.join(MODELS_DIR, "phishing_model.pkl")

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
# Rule-based fallback (works before any model is trained)
# This mirrors what CognitoMail already does — so the extension is
# useful from day one, even without ML.
# ---------------------------------------------------------------------------

def rule_based_score(email: dict) -> dict:
    """
    Returns a score 0–100 and a list of triggered rules.
    Used when the ML model isn't available yet.
    """
    score  = 0
    flags  = []
    feats  = extract_features(email)

    # Auth failures
    if feats[0] == 0:  score += 15; flags.append("SPF check failed or missing")
    if feats[1] == 0:  score += 15; flags.append("DKIM check failed or missing")
    if feats[2] == 0:  score += 10; flags.append("DMARC check failed or missing")

    # Urgency words in subject/body
    if feats[8]  > 0:  score += 10; flags.append(f"Urgency words in subject ({int(feats[8])})")
    if feats[12] > 1:  score += 10; flags.append(f"Multiple urgency words in body ({int(feats[12])})")

    # Credential harvesting words
    if feats[14] > 0:  score += 15; flags.append("Credential-related words detected")

    # Brand impersonation
    if feats[15] > 0:  score += 10; flags.append(f"Known brand name in email ({int(feats[15])})")

    # Suspicious URLs
    if feats[21] == 1: score += 20; flags.append("URL contains an IP address instead of a domain")
    if feats[22] > 0:  score += 15; flags.append(f"Suspicious top-level domain ({int(feats[22])})")
    if feats[23] > 0:  score += 10; flags.append(f"Non-HTTPS URLs found ({int(feats[23])})")

    # HTML tricks
    if feats[27] > 0:  score += 10; flags.append("HTML form elements detected")
    if feats[28] > 0:  score += 15; flags.append("Hidden text elements detected")
    if feats[29] > 0:  score += 10; flags.append("Redirect links detected")

    score = min(score, 100)

    if score >= 70:
        verdict, colour = "Phishing", "red"
    elif score >= 40:
        verdict, colour = "Suspicious", "orange"
    else:
        verdict, colour = "Likely Safe", "green"

    return {
        "verdict":     verdict,
        "risk_score":  score,
        "colour":      colour,
        "flags":       flags,
        "method":      "rule-based",
        "confidence":  None,
    }


# ---------------------------------------------------------------------------
# ML-based analysis
# ---------------------------------------------------------------------------

def ml_score(email: dict) -> dict:
    feats = np.array([extract_features(email)], dtype=np.float32)

    proba     = pipeline.predict_proba(feats)[0]   # [P(legit), P(phishing)]
    phish_prob = float(proba[1])
    risk_score = int(phish_prob * 100)

    if phish_prob >= 0.75:
        verdict, colour = "Phishing", "red"
    elif phish_prob >= 0.45:
        verdict, colour = "Suspicious", "orange"
    else:
        verdict, colour = "Likely Safe", "green"

    # Human-readable contributing factors
    # Use feature values to explain which signals drove the score
    feat_vals  = feats[0]
    flags = []

    if feat_vals[0] == 0: flags.append("SPF authentication failed")
    if feat_vals[1] == 0: flags.append("DKIM authentication failed")
    if feat_vals[2] == 0: flags.append("DMARC authentication failed")
    if feat_vals[8]  > 0: flags.append(f"Urgency words in subject")
    if feat_vals[12] > 1: flags.append(f"Multiple urgency words in body")
    if feat_vals[14] > 0: flags.append("Credential-harvesting language detected")
    if feat_vals[15] > 0: flags.append("Brand name impersonation detected")
    if feat_vals[21]:     flags.append("URL uses IP address instead of domain name")
    if feat_vals[22] > 0: flags.append("Suspicious top-level domain in URL")
    if feat_vals[23] > 0: flags.append("Non-HTTPS links present")
    if feat_vals[28] > 0: flags.append("Hidden content elements in email")
    if feat_vals[29] > 0: flags.append("Redirect links detected")

    if not flags:
        if phish_prob < 0.45:
            flags.append("No significant phishing signals detected")
        else:
            flags.append("Combination of low-level signals raised suspicion")

    return {
        "verdict":     verdict,
        "risk_score":  risk_score,
        "colour":      colour,
        "flags":       flags,
        "method":      "ml",
        "confidence":  round(phish_prob, 4),
    }


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":       "ok",
        "model_loaded": pipeline is not None,
    })


@app.route("/model-info", methods=["GET"])
def model_info():
    if pipeline is None:
        return jsonify({"error": "No model loaded. Run train_model.py first."}), 503

    clf = pipeline.named_steps["clf"]
    return jsonify({
        "model_type":     type(clf).__name__,
        "feature_count":  len(FEATURE_NAMES),
        "feature_names":  FEATURE_NAMES,
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Expects JSON body:
    {
        "sender":  "someone@example.com",
        "subject": "Urgent: verify your account",
        "body":    "Dear user, click here...",
        "urls":    ["http://evil.ru/login"],
        "spf":     "fail",
        "dkim":    "fail",
        "dmarc":   "none"
    }

    Returns:
    {
        "verdict":    "Phishing" | "Suspicious" | "Likely Safe",
        "risk_score": 0–100,
        "colour":     "red" | "orange" | "green",
        "flags":      ["reason 1", "reason 2", ...],
        "method":     "ml" | "rule-based",
        "confidence": 0.0–1.0 | null
    }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    # Basic validation
    email_dict = {
        "sender":  str(data.get("sender",  "")),
        "subject": str(data.get("subject", "")),
        "body":    str(data.get("body",    "")),
        "urls":    data.get("urls", []),
        "spf":     str(data.get("spf",  "none")),
        "dkim":    str(data.get("dkim", "none")),
        "dmarc":   str(data.get("dmarc","none")),
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

    log.info(
        f"Analyzed email | verdict={result['verdict']} "
        f"score={result['risk_score']} method={result['method']}"
    )
    return jsonify(result)


# ---------------------------------------------------------------------------
# Feedback endpoint — user corrections feed future retraining
# ---------------------------------------------------------------------------

@app.route("/feedback", methods=["POST"])
def feedback():
    """
    Called when a user confirms or corrects the extension's verdict.
    The extension sends this after the user clicks "Mark as Phishing"
    or "Mark as Safe" on a result they think is wrong.

    Body:
    {
        "email":            { ...same email dict as /analyze... },
        "predicted_label":  0 or 1,
        "correct_label":    0 or 1
    }

    This does NOT immediately retrain — it logs to feedback_log.csv
    for you to review and retrain from manually. This prevents the
    model from learning bad labels if a user makes a mistake.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    email_dict      = data.get("email", {})
    predicted_label = int(data.get("predicted_label", -1))
    correct_label   = int(data.get("correct_label", -1))

    if predicted_label not in (0, 1) or correct_label not in (0, 1):
        return jsonify({"error": "predicted_label and correct_label must be 0 or 1"}), 400

    try:
        from train_model import log_feedback
        log_feedback(email_dict, predicted_label, correct_label)
        log.info(f"Feedback logged: predicted={predicted_label} correct={correct_label}")
        return jsonify({"status": "logged", "message": "Thank you — this will improve future detection."})
    except Exception as e:
        log.error(f"Feedback logging error: {e}")
        return jsonify({"error": "Failed to log feedback"}), 500


# ---------------------------------------------------------------------------
# Dev server
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(debug=True, host="0.0.0.0", port=port)
