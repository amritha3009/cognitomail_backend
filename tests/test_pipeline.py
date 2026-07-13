"""
test_pipeline.py
----------------
Quick smoke test — run this to confirm the full pipeline works
before touching any real datasets.

    cd cognitomail_backend
    python tests/test_pipeline.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from feature_extractor import extract_features, FEATURE_NAMES
from dataset_loader import build_dataset
from train_model import train

print("=" * 55)
print("CognitoMail — Pipeline Smoke Test")
print("=" * 55)

# 1. Feature extractor
print("\n[1] Testing feature extractor...")
sample_phishing = {
    "sender":  "security@paypa1-secure.ru",
    "subject": "URGENT: Your account has been suspended!",
    "body":    "Dear user, verify your PayPal credentials immediately or your account will be closed. Click: http://192.168.0.1/login",
    "urls":    ["http://192.168.0.1/login", "http://evil.tk/steal"],
    "spf":     "fail",
    "dkim":    "fail",
    "dmarc":   "none",
}
sample_legit = {
    "sender":  "newsletter@company.com",
    "subject": "Monthly update — June 2026",
    "body":    "Hello, here is your monthly digest. Thanks for reading!",
    "urls":    ["https://company.com/blog"],
    "spf":     "pass",
    "dkim":    "pass",
    "dmarc":   "pass",
}

phish_feats = extract_features(sample_phishing)
legit_feats  = extract_features(sample_legit)

assert len(phish_feats) == 30, f"Expected 30 features, got {len(phish_feats)}"
assert len(FEATURE_NAMES) == 30
print(f"   Features extracted: {len(phish_feats)} ✓")
print(f"   Phishing SPF score : {phish_feats[0]} (expected 0)")
print(f"   Legit SPF score    : {legit_feats[0]} (expected 1)")

# 2. Dataset builder
print("\n[2] Testing dataset builder...")
records = [
    {**sample_phishing, "label": 1},
    {**sample_legit,    "label": 0},
]
X, y = build_dataset(records)
assert X.shape == (2, 30)
assert list(y) == [1, 0]
print(f"   X shape: {X.shape} ✓")
print(f"   y values: {list(y)} ✓")

# 3. Full train (uses synthetic fallback since no real data yet)
print("\n[3] Running full training pipeline (synthetic data)...")
pipeline = train(use_synthetic_fallback=True)

# 4. Predict on samples
import numpy as np
Xp = np.array([phish_feats], dtype=float)
Xl = np.array([legit_feats],  dtype=float)
pred_p = pipeline.predict(Xp)[0]
pred_l = pipeline.predict(Xl)[0]
prob_p = pipeline.predict_proba(Xp)[0][1]
prob_l = pipeline.predict_proba(Xl)[0][1]

print(f"\n[4] Predictions on hand-crafted samples:")
print(f"   Phishing email → predicted={'Phishing' if pred_p==1 else 'Legit'} | P(phish)={prob_p:.3f}")
print(f"   Legit email    → predicted={'Phishing' if pred_l==1 else 'Legit'} | P(phish)={prob_l:.3f}")

print("\n" + "=" * 55)
print("All tests passed! ✓")
print("Next: add real datasets to data/raw/ then re-run train_model.py")
print("=" * 55)
