# AI-Powered Phishing Detection System

Detects phishing URLs and emails with Scikit-learn models and returns a 0 to 100 risk score with plain-language warning signs.

**Stack:** Python, Scikit-learn, Flask, React.js, PostgreSQL

## How it works

| Input | Features | Model | Explanation |
|---|---|---|---|
| URL | 26 lexical features (length, IP host, `@`, punycode, subdomain depth, TLD, shortener, brand name outside the real domain, host entropy, and more) | Random forest | Rule-based indicators computed from the same features |
| Email | 18 header and body signals (urgency wording, credential requests, link text vs. real link, reply-to mismatch, free-mail sender, link risk) plus TF-IDF of the text | Logistic regression | Rule-based indicators, flagged links, and the words that pushed the score up (TF-IDF weight x coefficient) |

Risk score = model probability x 100. Below 35 is low, 35 to 69 is medium, 70 and above is high.

URLs are only parsed as text. The server never requests them.

## Project layout

```
backend/
  app/
    __init__.py        app factory, security headers, JWT error handlers
    config.py          settings from environment variables
    routes.py          REST API and error handlers
    validators.py      input validation
    privacy.py         hashing and redaction before anything is stored
    models.py          User and Scan tables (SQLAlchemy)
    ml/
      url_features.py, email_features.py   feature extraction and indicators
      train.py         training CLI
      synthetic.py     demo data generator
      predictor.py     model loading, scoring, explanations
  tests/
frontend/              React (Vite) app
docker-compose.yml     PostgreSQL for local development
```

## Quick start

**1. Database**

```bash
docker compose up -d db
```

**2. Backend**

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # then set JWT_SECRET_KEY
set -a && source .env && set +a

python -m app.ml.train --demo   # trains on synthetic data, see "Training on real data"
python run.py                   # http://127.0.0.1:5000
```

Tables are created on startup. Without `DATABASE_URL` the app falls back to a local SQLite file.

**3. Frontend**

```bash
cd frontend
npm install
npm run dev                     # http://localhost:5173, proxies /api to Flask
```

**4. Tests**

```bash
cd backend && pytest
```

## API

All bodies are JSON. Errors look like `{"error": {"code": "...", "message": "...", "field": "..."}}`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/health` | no | Status and model version |
| POST | `/api/auth/register` | no | `{email, password}` (10+ characters, letter and digit) |
| POST | `/api/auth/login` | no | Returns `access_token` |
| POST | `/api/scan/url` | Bearer | `{url}` |
| POST | `/api/scan/email` | Bearer | `{sender?, reply_to?, subject?, body}` |
| GET | `/api/scans?page=&per_page=` | Bearer | Your history, newest first |
| GET | `/api/scans/<id>` | Bearer | One result |
| DELETE | `/api/scans/<id>` | Bearer | Delete one result |
| DELETE | `/api/scans` | Bearer | Delete all your results |

Example:

```bash
TOKEN=$(curl -s localhost:5000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"correct-horse-42"}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s localhost:5000/api/scan/url -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"url":"http://paypal.secure-login.xyz/verify"}'
```

## Security measures

- **Input validation:** type, length, control-character and format checks on every field (`validators.py`). Request bodies over 256 KB are rejected.
- **Authentication:** password hashes via Werkzeug (scrypt), JWT access tokens that expire after 30 minutes (`JWT_EXPIRES_MINUTES`). Login gives the same response for an unknown email and a wrong password.
- **Rate limiting:** 5 registrations, 10 logins and 30 scans per minute per IP, 200 requests per hour overall. Set `RATELIMIT_STORAGE_URI=redis://...` when running more than one worker.
- **Data protection:** raw email bodies and full URLs are never stored. The database keeps a SHA-256 of the input, a redacted preview (URL without query string or fragment, subject with email addresses and long numbers masked) and the result. Users can delete their history. Each user can only read their own scans.
- **Injection and XSS:** all queries go through the SQLAlchemy ORM. React escapes all output, and the API sends `default-src 'none'` and other hardening headers.
- **Safe analysis:** the server never fetches submitted URLs, so scanning cannot cause SSRF or tip off an attacker.
- **Secrets:** `JWT_SECRET_KEY` must be set when `APP_ENV=production`, otherwise the app refuses to start.

## Before production

- Put the API behind HTTPS and set `APP_ENV=production` (enables HSTS).
- If behind a reverse proxy, apply `werkzeug.middleware.proxy_fix.ProxyFix` so rate limits see the real client IP.
- The frontend keeps the token in `sessionStorage`. That survives a refresh but is readable by any script on the page. For stricter setups, move to an HttpOnly cookie with CSRF protection.
- Tokens are not revocable before they expire. Add a denylist if you need immediate logout.
- Replace `db.create_all()` with Alembic migrations once the schema changes.
- Model files are pickles. Only load files produced by your own training runs.

## Training on real data

`--demo` trains on generated patterns so the project runs without downloads. The near-perfect metrics it prints are not meaningful. For real detection, train on labelled data:

```bash
python -m app.ml.train --urls data/urls.csv --emails data/emails.csv
```

| File | Columns | Label |
|---|---|---|
| `urls.csv` | `url,label` | 1 phishing, 0 legitimate |
| `emails.csv` | `sender,reply_to,subject,body,label` | 1 phishing, 0 legitimate |

Possible sources: phishing URL feeds such as PhishTank or OpenPhish, a top-sites list for legitimate URLs, and public email corpora such as SpamAssassin, Enron, or a phishing email dataset from Kaggle. Check each licence. Keep the class balance and time ordering of your data in mind: a random split on URLs from the same campaign will overstate accuracy.

The training script reports accuracy, precision, recall, F1 and ROC AUC on a held-out 20% split and saves them in `models/metadata.json`.

## Limitations

- URL features are lexical only. There is no lookup of domain age, WHOIS, page content, or reputation feeds, so a well-crafted phishing link on a clean-looking domain can score low.
- A low score does not mean a message or site is safe.
