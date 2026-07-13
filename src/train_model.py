"""
train_model.py
--------------
Trains a Random Forest classifier on all available datasets and saves
the model + scaler to disk.

Run:
    cd cognitomail_backend
    python src/train_model.py

Output:
    models/phishing_model.pkl     ← trained classifier
    models/scaler.pkl             ← feature scaler
    models/training_report.txt    ← accuracy, confusion matrix, feature importance
"""

import os
import sys
import logging
import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, accuracy_score
)
from sklearn.pipeline import Pipeline

# Make sure src/ is on the path when run from project root
sys.path.insert(0, os.path.dirname(__file__))

from dataset_loader import load_all_datasets, build_dataset
from feature_extractor import FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
os.makedirs(MODELS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Model definitions — swap MODEL_NAME to try different classifiers
# ---------------------------------------------------------------------------

MODEL_NAME = "random_forest"   # options: "random_forest", "gradient_boosting", "logistic_regression"

MODELS = {
    "random_forest": RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced",   # handles imbalanced datasets automatically
        random_state=42,
        n_jobs=-1,
    ),
    "gradient_boosting": GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.1,
        max_depth=5,
        random_state=42,
    ),
    "logistic_regression": LogisticRegression(
        C=1.0,
        class_weight="balanced",
        max_iter=1000,
        random_state=42,
    ),
}


# ---------------------------------------------------------------------------
# Training pipeline
# ---------------------------------------------------------------------------

def train(use_synthetic_fallback: bool = True):
    """
    Main training function.

    use_synthetic_fallback: if no real datasets are found, generate a small
    synthetic dataset so you can at least test the full pipeline works.

    DATA SEPARATION RULES (important for your thesis):
    ---------------------------------------------------
    - Public datasets (PhiUSIIL, SpamAssassin, Nazario, CEAS) → training + CV
    - data/raw/custom_emails.csv  → HELD OUT, never seen during training
      This is where your Gmail simulation emails live.
      They are used ONLY for final evaluation to avoid overfitting.
    - data/raw/feedback_log.csv   → collected during live use, for future retraining
    """

    log.info("=" * 60)
    log.info("CognitoMail — Phishing Detection Model Trainer")
    log.info("=" * 60)

    # 1. Load public datasets ONLY for training (no custom/simulation emails)
    records = _load_public_datasets_only()

    if len(records) < 50:
        if use_synthetic_fallback:
            log.warning("Not enough real data. Generating synthetic examples for pipeline testing.")
            records = _generate_synthetic_data(n=500)
        else:
            log.error("Not enough training data. Add datasets to data/raw/ and retry.")
            sys.exit(1)

    # 2. Build feature matrix
    log.info("Extracting features...")
    X, y = build_dataset(records)
    log.info(f"Dataset shape: X={X.shape}, y={y.shape}")
    log.info(f"Class balance — Legit: {(y==0).sum()}  Phishing: {(y==1).sum()}")

    # 3. Train/test split (stratified = keeps class ratio in both splits)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    log.info(f"Train: {len(X_train)} samples  |  Test: {len(X_test)} samples")

    # 4. Build pipeline (scaler + model)
    clf = MODELS[MODEL_NAME]
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    clf),
    ])

    # 5. Cross-validation on training set (5-fold)
    log.info(f"Running 5-fold cross-validation with {MODEL_NAME}...")
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=5, scoring="f1", n_jobs=-1)
    log.info(f"CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # 6. Final fit on full training set
    log.info("Training final model on full training set...")
    pipeline.fit(X_train, y_train)

    # 7. Evaluate on held-out test set
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_proba)
    cm   = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])

    log.info(f"\nTest Accuracy : {acc:.4f}")
    log.info(f"ROC-AUC       : {auc:.4f}")
    log.info(f"\nConfusion Matrix:\n{cm}")
    log.info(f"\nClassification Report:\n{report}")

    # 8. Feature importance (Random Forest / Gradient Boosting only)
    importance_lines = []
    if hasattr(clf, "feature_importances_"):
        scaler_step = pipeline.named_steps["scaler"]
        importances = pipeline.named_steps["clf"].feature_importances_
        ranked = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
        importance_lines = [f"  {name:<40} {score:.4f}" for name, score in ranked]
        log.info("\nTop 10 most important features:")
        for line in importance_lines[:10]:
            log.info(line)

    # 9. Save model and scaler separately (for Flask API use)
    model_path  = os.path.join(MODELS_DIR, "phishing_model.pkl")
    joblib.dump(pipeline, model_path)
    log.info(f"\nModel saved to {model_path}")

    # Also save scaler separately for inspection
    scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
    joblib.dump(pipeline.named_steps["scaler"], scaler_path)

    # 10. Write human-readable training report
    report_path = os.path.join(MODELS_DIR, "training_report.txt")
    with open(report_path, "w") as f:
        f.write("CognitoMail — Phishing Detection Training Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Model        : {MODEL_NAME}\n")
        f.write(f"Total samples: {len(records)}\n")
        f.write(f"  Legitimate : {(y==0).sum()}\n")
        f.write(f"  Phishing   : {(y==1).sum()}\n\n")
        f.write(f"CV F1 (5-fold): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}\n")
        f.write(f"Test Accuracy : {acc:.4f}\n")
        f.write(f"ROC-AUC       : {auc:.4f}\n\n")
        f.write(f"Confusion Matrix:\n{cm}\n\n")
        f.write(f"Classification Report:\n{report}\n")
        if importance_lines:
            f.write("\nFeature Importances (all 30):\n")
            f.write("\n".join(importance_lines) + "\n")

    # 10b. Evaluate on held-out simulation emails (kept strictly separate)
    _evaluate_on_simulation_emails(pipeline, report_file=report_path)

    log.info(f"Training report saved to {report_path}")
    log.info("\nTraining complete!")
    return pipeline


# ---------------------------------------------------------------------------
# Dataset separation helpers
# ---------------------------------------------------------------------------

def _load_public_datasets_only() -> list:
    """
    Loads ONLY public datasets — never custom_emails.csv.
    custom_emails.csv is reserved for held-out simulation evaluation.
    """
    from dataset_loader import load_phiusiil, load_spamassassin, load_nazario, load_ceas08
    records = []
    records += load_phiusiil()
    records += load_spamassassin()
    records += load_nazario()
    records += load_ceas08()
    log.info(f"Public datasets total: {len(records)} records (simulation emails excluded)")
    return records


def _evaluate_on_simulation_emails(pipeline, report_file: str = None):
    """
    Evaluates the trained model on custom_emails.csv WITHOUT having trained on them.
    This is your held-out test set — your Gmail simulation emails go here.

    Results are appended to the training report and printed to console.
    """
    from dataset_loader import load_custom, build_dataset

    sim_records = load_custom()
    if not sim_records:
        log.info("No simulation emails found in custom_emails.csv — skipping held-out evaluation.")
        return

    X_sim, y_sim = build_dataset(sim_records)
    if len(X_sim) == 0:
        return

    y_pred  = pipeline.predict(X_sim)
    y_proba = pipeline.predict_proba(X_sim)[:, 1]

    log.info("\n" + "=" * 60)
    log.info("HELD-OUT EVALUATION — Simulation emails (never seen in training)")
    log.info("=" * 60)

    for i, rec in enumerate(sim_records):
        verdict  = "PHISHING" if y_pred[i] == 1 else "LEGIT"
        actual   = "PHISHING" if rec["label"] == 1 else "LEGIT"
        correct  = "✓" if y_pred[i] == rec["label"] else "✗"
        log.info(
            f"  {correct} [{actual:8}] → predicted {verdict:8} "
            f"(P={y_proba[i]:.3f})  subject: {rec['subject'][:50]}"
        )

    correct_count = sum(y_pred[i] == rec["label"] for i, rec in enumerate(sim_records))
    sim_acc = correct_count / len(sim_records)
    log.info(f"\n  Simulation accuracy: {sim_acc:.2f} ({correct_count}/{len(sim_records)})")
    log.info("=" * 60)

    if report_file and os.path.exists(report_file):
        with open(report_file, "a") as f:
            f.write("\n\nHELD-OUT EVALUATION — Simulation Emails\n")
            f.write("=" * 60 + "\n")
            f.write("These emails were NEVER seen during training.\n\n")
            for i, rec in enumerate(sim_records):
                verdict = "PHISHING" if y_pred[i] == 1 else "LEGIT"
                actual  = "PHISHING" if rec["label"] == 1 else "LEGIT"
                correct = "CORRECT" if y_pred[i] == rec["label"] else "WRONG"
                f.write(
                    f"  [{correct}] actual={actual}, predicted={verdict}, "
                    f"P={y_proba[i]:.3f} | {rec['subject'][:60]}\n"
                )
            f.write(f"\nSimulation accuracy: {sim_acc:.2f} ({correct_count}/{len(sim_records)})\n")


# ---------------------------------------------------------------------------
# Feedback logging — for future retraining (online learning foundation)
# ---------------------------------------------------------------------------

def log_feedback(email: dict, predicted_label: int, correct_label: int):
    """
    Call this from app.py when a user confirms or corrects a verdict.
    Appends the email + correct label to data/raw/feedback_log.csv.

    This is NOT used in training yet — it builds a dataset for future
    retraining rounds. Prevents overfitting by keeping feedback separate
    until you have enough samples for a meaningful retrain.

    Usage in app.py:
        if user clicked "Mark as Phishing":
            log_feedback(email_dict, predicted=0, correct=1)
    """
    import csv
    feedback_path = os.path.join(
        os.path.dirname(__file__), "..", "data", "raw", "feedback_log.csv"
    )
    os.makedirs(os.path.dirname(feedback_path), exist_ok=True)

    fieldnames = ["sender", "subject", "body", "urls", "spf", "dkim", "dmarc",
                  "predicted_label", "label"]
    file_exists = os.path.exists(feedback_path)

    with open(feedback_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow({
            "sender":          email.get("sender", ""),
            "subject":         email.get("subject", ""),
            "body":            email.get("body", "")[:500],   # truncate for storage
            "urls":            "|".join(email.get("urls", [])),
            "spf":             email.get("spf", "none"),
            "dkim":            email.get("dkim", "none"),
            "dmarc":           email.get("dmarc", "none"),
            "predicted_label": predicted_label,
            "label":           correct_label,
        })

    # Remind researcher when enough feedback for a retrain has accumulated
    try:
        with open(feedback_path, "r") as f:
            count = sum(1 for _ in f) - 1   # subtract header
        if count > 0 and count % 50 == 0:
            log.info(
                f"Feedback log now has {count} entries. "
                f"Consider retraining: move feedback_log.csv entries into "
                f"a new dataset and run train_model.py."
            )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Synthetic data fallback (used when no datasets are present yet)
# Lets you verify the full pipeline works before adding real data.
# ---------------------------------------------------------------------------

def _generate_synthetic_data(n: int = 500) -> list:
    """
    Generates simple rule-based synthetic emails.
    NOT a substitute for real data — only for pipeline smoke-testing.
    """
    import random
    random.seed(42)

    records = []

    phishing_subjects = [
        "Urgent: Your account has been suspended",
        "Verify your PayPal information immediately",
        "You have won a $1000 Amazon gift card",
        "Your password will expire in 24 hours",
        "Important: Confirm your banking details",
    ]
    legit_subjects = [
        "Team meeting rescheduled to Thursday",
        "Your order has been shipped",
        "Monthly newsletter — June 2026",
        "Project update from the dev team",
        "Welcome to our service",
    ]

    phishing_bodies = [
        "Dear user, click here immediately to verify your account or it will be suspended: http://192.168.1.1/login",
        "Congratulations! You have been selected for a free reward. Provide your credit card details to claim.",
        "Your PayPal account has been limited. Login at http://paypa1-secure.ru/verify to restore access.",
    ]
    legit_bodies = [
        "Hi team, just a reminder that the meeting has been moved to 3pm on Thursday. See you then.",
        "Your order #12345 has been dispatched and will arrive within 3-5 business days.",
        "Here is the monthly newsletter with updates from our team.",
    ]

    for i in range(n):
        is_phishing = i % 2 == 0   # balanced 50/50
        records.append({
            "sender":  f"{'noreply@paypa1-secure.ru' if is_phishing else 'noreply@legit-company.com'}",
            "subject": random.choice(phishing_subjects if is_phishing else legit_subjects),
            "body":    random.choice(phishing_bodies   if is_phishing else legit_bodies),
            "urls":    (["http://192.168.1.1/verify"] if is_phishing else ["https://legit.com/order"]),
            "spf":     ("fail" if is_phishing else "pass"),
            "dkim":    ("fail" if is_phishing else "pass"),
            "dmarc":   ("fail" if is_phishing else "pass"),
            "label":   1 if is_phishing else 0,
        })

    return records


if __name__ == "__main__":
    train()
