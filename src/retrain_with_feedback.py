"""
retrain_with_feedback.py
------------------------
Merges public data + feedback_log.csv and retrains the model.

Run:
    cd cognitomail_backend
    python src/retrain_with_feedback.py
"""

import os
import sys
import csv
import logging
import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score
from sklearn.pipeline import Pipeline

sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import extract_features, FEATURE_NAMES
from train_model import _load_public_datasets_only, _generate_synthetic_data
from dataset_loader import build_dataset

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
FEEDBACK_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "feedback_log.csv")
RANDOM_SEED = 42


def load_feedback_records():
    """Load user corrections from feedback_log.csv as training records."""
    if not os.path.exists(FEEDBACK_PATH):
        log.info("No feedback_log.csv yet.")
        return []

    records = []
    with open(FEEDBACK_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                label = int(row.get("label", -1))
                if label not in (0, 1):
                    continue
                urls = [u for u in (row.get("urls") or "").split("|") if u]
                records.append({
                    "sender":  row.get("sender", ""),
                    "subject": row.get("subject", ""),
                    "body":    row.get("body", ""),
                    "urls":    urls,
                    "spf":     row.get("spf", "none"),
                    "dkim":    row.get("dkim", "none"),
                    "dmarc":   row.get("dmarc", "none"),
                    "label":   label,
                })
            except Exception:
                continue

    log.info(f"Loaded {len(records)} feedback samples")
    return records


def retrain():
    log.info("=" * 60)
    log.info("Retrain with live feedback")
    log.info("=" * 60)

    public = _load_public_datasets_only()
    feedback = load_feedback_records()

    if len(public) < 50 and not feedback:
        log.warning("Little data — using synthetic fallback")
        public = _generate_synthetic_data(n=500)

    # Feedback is more valuable: optionally oversample it
    records = public + feedback * 3  # weight corrections x3
    log.info(f"Total records for training: {len(records)} "
             f"(public={len(public)}, feedback×3={len(feedback)*3})")

    X, y = build_dataset(records)
    if len(X) < 20:
        log.error("Not enough samples to retrain.")
        return

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", clf),
    ])

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    cv_f1 = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1")
    log.info(f"CV F1: {cv_f1.mean():.4f} ± {cv_f1.std():.4f}")

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba) if len(np.unique(y_test)) > 1 else 0.0
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])

    log.info(f"Test Accuracy: {acc:.4f}  ROC-AUC: {auc:.4f}")
    log.info(f"Confusion matrix:\n{cm}")
    log.info(f"\n{report}")

    os.makedirs(MODELS_DIR, exist_ok=True)
    model_path = os.path.join(MODELS_DIR, "phishing_model.pkl")
    joblib.dump(pipeline, model_path)
    log.info(f"Model saved → {model_path}")

    report_path = os.path.join(MODELS_DIR, "retrain_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("CognitoMail — Retrain with Feedback Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Public samples   : {len(public)}\n")
        f.write(f"Feedback samples : {len(feedback)} (×3 in training)\n")
        f.write(f"CV F1            : {cv_f1.mean():.4f} ± {cv_f1.std():.4f}\n")
        f.write(f"Test Accuracy    : {acc:.4f}\n")
        f.write(f"ROC-AUC          : {auc:.4f}\n\n")
        f.write(f"Confusion Matrix:\n{cm}\n\n")
        f.write(report)
    log.info(f"Report saved → {report_path}")
    log.info("Done. Redeploy the new phishing_model.pkl on Render.")


if __name__ == "__main__":
    retrain()