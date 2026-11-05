# AI-Powered Phishing Detection System

Phishing messages and fake websites are designed to look trustworthy. They can
pressure people into sharing passwords, payment details, or other sensitive
information. Recognising these attacks should not require specialist security
knowledge.

## The solution

This project is a web-based assistant that analyses website URLs and email
content for common phishing signals. It combines machine-learning models with
clear explanations so users can make more informed decisions before clicking,
replying, or sharing information.

The result is a risk score from **0 to 100**, a low/medium/high risk level, a
verdict, and the indicators that influenced the result.

## Features

- **URL scanning** - checks the structure and characteristics of website links
  without opening the sites.
- **Email scanning** - analyses sender details, subject, message text, and
  links for suspicious patterns.
- **Understandable results** - explains warning signs instead of showing only a
  model prediction.
- **User accounts** - keeps scan history separated between users.
- **Privacy-minded history** - stores redacted previews, fingerprints, and
  analysis results rather than complete email bodies or URLs.
- **History controls** - review or delete previous scans.
- **Request and input protection** - validates submissions and limits repeated
  requests.

## How it works

1. A user submits a URL or email through the web interface.
2. The backend validates the input and extracts security-relevant features.
3. A trained model estimates how strongly the input resembles phishing data.
4. The estimate becomes a risk score and risk level.
5. The interface presents the verdict, indicators, and supporting details.

### Risk levels

| Score | Level | Meaning |
| --- | --- | --- |
| 0-34 | Low | Fewer suspicious signals were detected. |
| 35-69 | Medium | Some suspicious characteristics were found. |
| 70-100 | High | Strong phishing-related warning signs were detected. |

## Benefits

- **Earlier decisions:** identify warning signs before interacting with a
  suspicious link or message.
- **Accessible security:** receive practical explanations without needing
  machine-learning expertise.
- **One place for two threats:** scan both URLs and emails in the same tool.
- **Better awareness:** learn the patterns commonly used in phishing attacks.
- **Privacy-conscious design:** reduce the amount of sensitive content retained
  in scan history.

## Quick start

### Requirements

Python, Node.js/npm, and either PostgreSQL or Docker.

```bash
cd phishing-detector
docker compose up -d db

cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env
python -m app.ml.train --demo
python run.py
```

In another terminal:

```bash
cd phishing-detector/frontend
npm install
npm run dev
```

The demo models are intended for local testing, not real-world security
decisions. A low score is not a guarantee that a URL or email is safe.

## Documentation

- [API reference](phishing-detector/docs/API.md) - endpoints, authentication,
  request bodies, responses, and errors.
- [Backend architecture](phishing-detector/docs/ARCHITECTURE.md) - application
  layers, data flow, machine-learning pipeline, and privacy boundaries.

## Technology

Python, Flask, scikit-learn, React, and PostgreSQL.
