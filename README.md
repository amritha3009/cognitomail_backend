# CognitoMail Backend — Setup & Training Guide

## Project Structure

```
cognitomail_backend/
│
├── src/
│   ├── feature_extractor.py   ← extracts 30 ML features from any email
│   ├── dataset_loader.py      ← loads & normalises all datasets
│   ├── train_model.py         ← trains the Random Forest model
│   └── app.py                 ← Flask API (what the extension calls)
│
├── data/
│   └── raw/                   ← YOU ADD DATASETS HERE (see below)
│       ├── custom_emails.csv  ← your own labelled examples (ready to edit)
│       ├── PhiUSIIL_Phishing_URL_Dataset.csv
│       ├── ceas08.csv
│       ├── spam_assassin/
│       │   ├── spam/          ← phishing/spam email files
│       │   └── ham/           ← legitimate email files
│       └── nazario/
│           ├── phishing/      ← .eml phishing files
│           └── ham/           ← .eml legitimate files (optional)
│
├── models/                    ← auto-created when you train
│   ├── phishing_model.pkl     ← trained model + scaler (pipeline)
│   └── training_report.txt   ← accuracy, confusion matrix, feature importance
│
├── tests/
│   └── test_pipeline.py       ← smoke test (run this first)
│
└── requirements.txt
```

---

## Step 1 — Install dependencies

```bash
cd cognitomail_backend
pip install -r requirements.txt
```

---

## Step 2 — Verify the pipeline works (no data needed yet)

```bash
python tests/test_pipeline.py
```

This uses synthetic data so you can confirm everything imports and runs
correctly before touching any real datasets. You should see:

```
All tests passed! ✓
Next: add real datasets to data/raw/ then re-run train_model.py
```

---

## Step 3 — Add real datasets

You need at least one dataset. Add as many as you like — the loader
picks up whichever files are present and skips the rest.

### Option A — PhiUSIIL (easiest, URL-focused)
1. Go to: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
2. Download `PhiUSIIL_Phishing_URL_Dataset.csv`
3. Place at: `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`

### Option B — SpamAssassin corpus (best for full email analysis)
1. Go to: https://spamassassin.apache.org/old/publiccorpus/
2. Download: `20030228_spam.tar.bz2` and `20030228_easy_ham.tar.bz2`
3. Extract and place files so you have:
   - `data/raw/spam_assassin/spam/`  ← spam email files
   - `data/raw/spam_assassin/ham/`   ← ham email files

### Option C — Nazario phishing corpus (real phishing .eml files)
1. Go to: https://monkey.org/~jose/phishing/
2. Download any `phishing*.tar.bz2` archive
3. Extract .eml files to: `data/raw/nazario/phishing/`

### Option D — Your own examples (custom_emails.csv)
The file `data/raw/custom_emails.csv` is already created with 4 sample rows.
Add your own rows following the same column format:

| Column  | Format                                      |
|---------|---------------------------------------------|
| sender  | email address string                        |
| subject | subject line text                           |
| body    | email body text                             |
| urls    | pipe-separated list of URLs (or empty)      |
| spf     | `pass`, `fail`, or `none`                   |
| dkim    | `pass`, `fail`, or `none`                   |
| dmarc   | `pass`, `fail`, or `none`                   |
| label   | `1` = phishing, `0` = legitimate            |

---

## Step 4 — Train the model

```bash
python src/train_model.py
```

This will:
- Load all datasets found in `data/raw/`
- Extract 30 features per email
- Train a Random Forest classifier
- Run 5-fold cross-validation
- Print accuracy, ROC-AUC, and confusion matrix
- Save the model to `models/phishing_model.pkl`
- Save a detailed report to `models/training_report.txt`

---

## Step 5 — Start the Flask API

```bash
python src/app.py
```

The server starts at `http://localhost:5050`

Test it immediately:

```bash
curl -X POST http://localhost:5050/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "sender":  "noreply@paypa1-secure.ru",
    "subject": "Urgent: Your account is suspended",
    "body":    "Click here to verify your PayPal credentials immediately",
    "urls":    ["http://192.168.0.1/login"],
    "spf":     "fail",
    "dkim":    "fail",
    "dmarc":   "none"
  }'
```

Expected response:
```json
{
  "verdict": "Phishing",
  "risk_score": 87,
  "colour": "red",
  "flags": ["SPF authentication failed", "DKIM authentication failed", ...],
  "method": "ml",
  "confidence": 0.87
}
```

---

## Step 6 — Deploy to Render (free tier)

1. Push the `cognitomail_backend/` folder to GitHub
2. Create a new Web Service on https://render.com
3. Set the start command to: `gunicorn src.app:app`
4. Set environment: Python 3.11

> **Important**: The trained model file (`models/phishing_model.pkl`) must be
> committed to your repo, OR you run `train_model.py` as part of the Render
> build command. Simplest approach: train locally, commit the `.pkl` file.

---

## The 30 ML Features

| # | Feature | What it captures |
|---|---------|-----------------|
| 1-3 | spf_pass, dkim_pass, dmarc_pass | Email authentication |
| 4-7 | free_email_domain, sender_entropy, sender_digits_ratio, display_name_mismatch | Sender deception |
| 8-11 | subject_length, subject_urgency_words, subject_all_caps_words, subject_exclamations | Subject manipulation |
| 12-18 | body_length, urgency/reward/credential word counts, brand_impersonation, caps_ratio, body_entropy | Body content analysis |
| 19-27 | url_count, avg_url_length, avg_url_entropy, has_ip_url, suspicious_tld, http_count, url_domain_variety, subdomain_depth, special_char_ratio | URL behavioural signals |
| 28-30 | html_form_elements, hidden_text_elements, redirect_link_count | HTML structure tricks |

---

## Troubleshooting

**"No trained model found"** → Run `python src/train_model.py` first.
The API works with rule-based scoring until the model is trained.

**"Not enough training data"** → Add at least one dataset from Step 3.
The custom CSV alone (with your own examples) is enough to test.

**Import errors** → Make sure you're running from `cognitomail_backend/`
as your working directory, not from inside `src/`.

**CORS errors from extension** → In `app.py`, change `"origins": "*"` to
your simulation's actual URL once you know it.
