"""
active_learning.py
------------------
Active-learning helpers for CognitoMail.

Uncertainty is highest when P(phishing) ≈ 0.5:
  uncertainty = 1 - |2P - 1|
"""

from __future__ import annotations
from typing import Any, Dict, Optional


UNCERTAIN_SCORE_LOW = 35
UNCERTAIN_SCORE_HIGH = 65
UNCERTAIN_PROB_MARGIN = 0.18  # |P - 0.5| < 0.18 → uncertain


def phishing_probability(result: Dict[str, Any]) -> float:
    conf = result.get("confidence")
    if conf is not None:
        try:
            return float(conf)
        except (TypeError, ValueError):
            pass
    try:
        return max(0.0, min(1.0, float(result.get("risk_score", 50)) / 100.0))
    except (TypeError, ValueError):
        return 0.5


def uncertainty_score(p_phish: float) -> float:
    p = max(0.0, min(1.0, float(p_phish)))
    return 1.0 - abs(2.0 * p - 1.0)


def is_uncertain(result: Dict[str, Any]) -> bool:
    p = phishing_probability(result)
    score = int(result.get("risk_score", 50) or 50)
    near_boundary = abs(p - 0.5) < UNCERTAIN_PROB_MARGIN
    mid_score = UNCERTAIN_SCORE_LOW <= score <= UNCERTAIN_SCORE_HIGH
    return near_boundary or mid_score


def active_learning_meta(result: Dict[str, Any]) -> Dict[str, Any]:
    p = phishing_probability(result)
    u = uncertainty_score(p)
    needs = is_uncertain(result)
    return {
        "p_phishing": round(p, 4),
        "uncertainty": round(u, 4),
        "needs_review": needs,
        "review_reason": (
            "Model confidence is near the decision boundary — your feedback is especially valuable."
            if needs
            else None
        ),
    }


def sample_weight_for_feedback(
    correct_label: int,
    predicted_label: int,
    uncertainty: Optional[float] = None,
    base_feedback_weight: float = 3.0,
) -> float:
    w = base_feedback_weight
    if int(correct_label) != int(predicted_label):
        w *= 1.5
    if uncertainty is not None:
        w *= 1.0 + 0.5 * max(0.0, min(1.0, float(uncertainty)))
    return round(w, 3)