"""
evaluate_and_plot.py
--------------------
Re-evaluates the trained model and generates thesis-ready plots.

Run from project root:
    cd cognitomail_backend
    python src/evaluate_and_plot.py

Outputs (saved in models/):
    confusion_matrix.png
    roc_curve.png
    precision_recall_curve.png
    feature_importance.png
    evaluation_report.txt
"""

import os
import sys
import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")  # non-interactive backend (works on servers too)
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    confusion_matrix, ConfusionMatrixDisplay,
    roc_curve, auc, precision_recall_curve,
    classification_report, accuracy_score, f1_score,
    precision_score, recall_score, roc_auc_score,
)

sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import FEATURE_NAMES
from train_model import _load_public_datasets_only, _generate_synthetic_data
from dataset_loader import build_dataset

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
os.makedirs(MODELS_DIR, exist_ok=True)

RANDOM_SEED = 42  # fixed for reproducibility


def main():
    print("=" * 60)
    print("CognitoMail — Evaluation & Plot Generator")
    print("=" * 60)

    # 1. Load data (same logic as training)
    records = _load_public_datasets_only()
    if len(records) < 50:
        print("Not enough real data — using synthetic fallback")
        records = _generate_synthetic_data(n=500)

    X, y = build_dataset(records)
    print(f"Dataset: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"  Legitimate: {(y==0).sum()}  Phishing: {(y==1).sum()}")

    # 2. Same split as training (seed=42)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    # 3. Load the already-trained pipeline
    model_path = os.path.join(MODELS_DIR, "phishing_model.pkl")
    if not os.path.exists(model_path):
        print("ERROR: models/phishing_model.pkl not found. Run train_model.py first.")
        sys.exit(1)

    pipeline = joblib.load(model_path)
    print(f"Model loaded from {model_path}")

    # 4. Predictions
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])

    # 5-fold CV F1 on training set (for the report)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    cv_f1 = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1")

    print(f"\nTest Accuracy : {acc:.4f}")
    print(f"Precision     : {prec:.4f}")
    print(f"Recall        : {rec:.4f}")
    print(f"F1            : {f1:.4f}")
    print(f"ROC-AUC       : {roc_auc:.4f}")
    print(f"CV F1         : {cv_f1.mean():.4f} ± {cv_f1.std():.4f}")
    print(f"\nConfusion Matrix:\n{cm}")
    print(f"\n{report}")

    # ── Plot 1: Confusion Matrix ──────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(6, 5))
    disp = ConfusionMatrixDisplay(cm, display_labels=["Legitimate", "Phishing"])
    disp.plot(cmap="Blues", ax=ax, colorbar=False)
    ax.set_title(f"Confusion Matrix\nAccuracy = {acc:.3f}")
    plt.tight_layout()
    path = os.path.join(MODELS_DIR, "confusion_matrix.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

    # ── Plot 2: ROC Curve ─────────────────────────────────────────────────
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, color="#00c9a7", lw=2, label=f"ROC AUC = {roc_auc:.3f}")
    ax.plot([0, 1], [0, 1], "k--", lw=1, label="Random")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve")
    ax.legend(loc="lower right")
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.05])
    plt.tight_layout()
    path = os.path.join(MODELS_DIR, "roc_curve.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

    # ── Plot 3: Precision-Recall Curve ────────────────────────────────────
    precision_vals, recall_vals, _ = precision_recall_curve(y_test, y_proba)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(recall_vals, precision_vals, color="#f9ab00", lw=2)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title(f"Precision-Recall Curve\nF1 = {f1:.3f}")
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.05])
    plt.tight_layout()
    path = os.path.join(MODELS_DIR, "precision_recall_curve.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

    # ── Plot 4: Feature Importance (top 15) ───────────────────────────────
    clf = pipeline.named_steps["clf"]
    if hasattr(clf, "feature_importances_"):
        importances = clf.feature_importances_
        idx = np.argsort(importances)[::-1][:15]
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.barh(range(len(idx)), importances[idx][::-1], color="#00c9a7")
        ax.set_yticks(range(len(idx)))
        ax.set_yticklabels([FEATURE_NAMES[i] for i in idx][::-1], fontsize=9)
        ax.set_xlabel("Importance")
        ax.set_title("Top 15 Feature Importances")
        plt.tight_layout()
        path = os.path.join(MODELS_DIR, "feature_importance.png")
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"Saved: {path}")
    else:
        print("Model has no feature_importances_ — skipping importance plot")

    # ── Text report ──────────────────────────────────────────────────────
    report_path = os.path.join(MODELS_DIR, "evaluation_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("CognitoMail — Evaluation Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Random seed     : {RANDOM_SEED}\n")
        f.write(f"Total samples   : {len(y)}\n")
        f.write(f"  Legitimate    : {(y==0).sum()}\n")
        f.write(f"  Phishing      : {(y==1).sum()}\n")
        f.write(f"Train / Test    : {len(y_train)} / {len(y_test)}\n\n")
        f.write(f"Test Accuracy   : {acc:.4f}\n")
        f.write(f"Precision       : {prec:.4f}\n")
        f.write(f"Recall          : {rec:.4f}\n")
        f.write(f"F1-score        : {f1:.4f}\n")
        f.write(f"ROC-AUC         : {roc_auc:.4f}\n")
        f.write(f"CV F1 (5-fold)  : {cv_f1.mean():.4f} ± {cv_f1.std():.4f}\n\n")
        f.write(f"Confusion Matrix:\n{cm}\n\n")
        f.write(f"Classification Report:\n{report}\n")
    print(f"Saved: {report_path}")

    print("\n" + "=" * 60)
    print("Done. All plots and report are in models/")
    print("=" * 60)


if __name__ == "__main__":
    main()