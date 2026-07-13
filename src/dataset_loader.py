"""
dataset_loader.py
-----------------
Loads and normalises phishing datasets into a standard format.

DATASETS SUPPORTED (you add the files — see README):
------------------------------------------------------
1. PhiUSIIL  →  data/raw/PhiUSIIL_Phishing_URL_Dataset.csv
2. SpamAssassin emails  →  data/raw/spam_assassin/  (folder of .txt files)
3. Nazario phishing corpus  →  data/raw/nazario/  (folder of .eml files)
4. CEAS 2008  →  data/raw/ceas08.csv
5. Your own labelled emails  →  data/raw/custom_emails.csv

Each loader returns a list of dicts:
[
    {
        "sender": str,
        "subject": str,
        "body": str,
        "urls": [str, ...],
        "spf": "none",       ← datasets without auth → default "none"
        "dkim": "none",
        "dmarc": "none",
        "label": 1           ← 1 = phishing, 0 = legitimate
    },
    ...
]

After loading, call build_dataset() to get (X, y) numpy arrays ready for training.
"""

import os
import re
import csv
import email
import glob
import logging
from email import policy
from email.parser import BytesParser, Parser

import numpy as np
from feature_extractor import extract_features

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _extract_urls_from_text(text: str) -> list:
    """Pull all http/https URLs from a block of text."""
    return re.findall(r"https?://[^\s\"'<>]+", text)


def _clean(text: str) -> str:
    return (text or "").strip()


# ---------------------------------------------------------------------------
# 1. PhiUSIIL — URL-only CSV dataset
#    Columns: url, label  (label: 1=phishing, 0=legit)
#    Download: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
# ---------------------------------------------------------------------------

def load_phiusiil(path: str = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv",
                  max_rows: int = 20000) -> list:
    """
    URL-only dataset. We synthesise a minimal email dict so the feature
    extractor still works — body/subject/auth fields are empty/none.
    """
    records = []
    if not os.path.exists(path):
        log.warning(f"PhiUSIIL not found at {path} — skipping.")
        return records

    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            url = row.get("url") or row.get("URL") or ""
            label_raw = row.get("label") or row.get("Label") or row.get("phishing") or "0"
            try:
                label = int(float(label_raw))
            except ValueError:
                continue

            records.append({
                "sender": "", "subject": "", "body": "",
                "urls": [url] if url else [],
                "spf": "none", "dkim": "none", "dmarc": "none",
                "label": label,
            })

    log.info(f"PhiUSIIL: loaded {len(records)} rows from {path}")
    return records


# ---------------------------------------------------------------------------
# 2. SpamAssassin public corpus
#    Folders: spam/ and ham/ inside data/raw/spam_assassin/
#    Download: https://spamassassin.apache.org/old/publiccorpus/
#    Each file is a raw RFC-822 email message.
# ---------------------------------------------------------------------------

def _parse_raw_email_file(filepath: str) -> dict:
    """Parse a raw .txt email file into our standard dict."""
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    sender  = str(msg.get("From", ""))
    subject = str(msg.get("Subject", ""))

    # Extract text body
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            pass

    body = " ".join(body_parts)
    urls = _extract_urls_from_text(body)

    return {
        "sender": _clean(sender),
        "subject": _clean(subject),
        "body": _clean(body),
        "urls": urls,
        "spf": "none", "dkim": "none", "dmarc": "none",
    }


def load_spamassassin(base_dir: str = "data/raw/spam_assassin",
                      max_per_class: int = 5000) -> list:
    """
    Expects:
        data/raw/spam_assassin/spam/   ← phishing/spam emails (label=1)
        data/raw/spam_assassin/ham/    ← legitimate emails   (label=0)
    """
    records = []
    if not os.path.isdir(base_dir):
        log.warning(f"SpamAssassin dir not found at {base_dir} — skipping.")
        return records

    for label, subdir in [(1, "spam"), (0, "ham")]:
        folder = os.path.join(base_dir, subdir)
        if not os.path.isdir(folder):
            log.warning(f"  Missing subfolder: {folder}")
            continue
        files = glob.glob(os.path.join(folder, "*"))[:max_per_class]
        for fp in files:
            try:
                rec = _parse_raw_email_file(fp)
                rec["label"] = label
                records.append(rec)
            except Exception as e:
                log.debug(f"  Skipping {fp}: {e}")

    log.info(f"SpamAssassin: loaded {len(records)} emails from {base_dir}")
    return records


# ---------------------------------------------------------------------------
# 3. Nazario phishing corpus
#    Download: https://monkey.org/~jose/phishing/  (phishing3.tar.bz2 etc.)
#    Each file is a raw .eml phishing email.
#    Put legit control emails in data/raw/nazario/ham/ if you have them,
#    otherwise only phishing samples are loaded (label=1).
# ---------------------------------------------------------------------------

def load_nazario(base_dir: str = "data/raw/nazario") -> list:
    """
    Expects:
        data/raw/nazario/phishing/  ← phishing .eml files (label=1)
        data/raw/nazario/ham/       ← legit .eml files    (label=0)  [optional]
    """
    records = []
    if not os.path.isdir(base_dir):
        log.warning(f"Nazario dir not found at {base_dir} — skipping.")
        return records

    for label, subdir in [(1, "phishing"), (0, "ham")]:
        folder = os.path.join(base_dir, subdir)
        if not os.path.isdir(folder):
            continue
        for fp in glob.glob(os.path.join(folder, "*.eml")) + \
                  glob.glob(os.path.join(folder, "*")):
            try:
                rec = _parse_raw_email_file(fp)
                rec["label"] = label
                records.append(rec)
            except Exception as e:
                log.debug(f"  Skipping {fp}: {e}")

    log.info(f"Nazario: loaded {len(records)} emails from {base_dir}")
    return records


# ---------------------------------------------------------------------------
# 4. CEAS 2008
#    CSV with columns: label, subject, body (sometimes sender)
#    label: 1=spam/phishing, 0=ham
#    Download: https://www.ceas.cc/2008/  (CEAS 2008 dataset)
# ---------------------------------------------------------------------------

def load_ceas08(path: str = "data/raw/ceas08.csv",
                max_rows: int = 15000) -> list:
    records = []
    if not os.path.exists(path):
        log.warning(f"CEAS08 not found at {path} — skipping.")
        return records

    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            try:
                label = int(row.get("label", row.get("Label", 0)))
            except ValueError:
                continue
            body    = row.get("body", row.get("Body", ""))
            subject = row.get("subject", row.get("Subject", ""))
            sender  = row.get("sender", row.get("From", ""))

            records.append({
                "sender": _clean(sender),
                "subject": _clean(subject),
                "body": _clean(body),
                "urls": _extract_urls_from_text(body),
                "spf": "none", "dkim": "none", "dmarc": "none",
                "label": label,
            })

    log.info(f"CEAS08: loaded {len(records)} rows from {path}")
    return records


# ---------------------------------------------------------------------------
# 5. Custom emails (your own labelled set)
#    CSV: sender, subject, body, urls (pipe-separated), spf, dkim, dmarc, label
#    Put it at data/raw/custom_emails.csv
# ---------------------------------------------------------------------------

def load_custom(path: str = "data/raw/custom_emails.csv") -> list:
    records = []
    if not os.path.exists(path):
        log.info(f"No custom dataset at {path} — skipping.")
        return records

    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                label = int(row.get("label", 0))
            except ValueError:
                continue
            urls_raw = row.get("urls", "")
            urls = [u.strip() for u in urls_raw.split("|") if u.strip()]
            records.append({
                "sender":  _clean(row.get("sender", "")),
                "subject": _clean(row.get("subject", "")),
                "body":    _clean(row.get("body", "")),
                "urls":    urls,
                "spf":     row.get("spf",  "none"),
                "dkim":    row.get("dkim", "none"),
                "dmarc":   row.get("dmarc","none"),
                "label":   label,
            })

    log.info(f"Custom: loaded {len(records)} rows from {path}")
    return records


# ---------------------------------------------------------------------------
# Master builder — call this to get training arrays
# ---------------------------------------------------------------------------

def build_dataset(records: list) -> tuple:
    """
    Convert a list of email dicts into (X, y) numpy arrays.

    X shape: (n_samples, 30)
    y shape: (n_samples,)   — 0=legit, 1=phishing
    """
    X, y = [], []
    skipped = 0
    for rec in records:
        try:
            feats = extract_features(rec)
            X.append(feats)
            y.append(int(rec["label"]))
        except Exception as e:
            skipped += 1
            log.debug(f"Skipping record: {e}")

    if skipped:
        log.warning(f"Skipped {skipped} records during feature extraction.")

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


def load_all_datasets() -> list:
    """Load every dataset that's present. Missing files are silently skipped."""
    records = []
    records += load_phiusiil()
    records += load_spamassassin()
    records += load_nazario()
    records += load_ceas08()
    records += load_custom()
    log.info(f"Total records loaded: {len(records)}")
    return records
