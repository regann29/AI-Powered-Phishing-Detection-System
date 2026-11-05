# Backend architecture

The backend is a Flask application that separates HTTP handling, validation,
feature extraction, prediction, and persistence. The frontend communicates
with it through JSON requests under `/api`.

## Request flow

```text
React UI
  -> Flask route and rate limit
  -> JSON/input validation
  -> feature extraction
  -> trained URL or email predictor
  -> risk score and explanations
  -> privacy-safe scan record
  -> JSON response
```

Authentication routes issue short-lived JWT access tokens. Protected routes
resolve the token to a user and only query or mutate scans owned by that user.

## Main components

| Component | Responsibility |
| --- | --- |
| `backend/app/routes.py` | HTTP endpoints, authentication, scan orchestration, and error responses. |
| `backend/app/validators.py` | JSON shape, length, email, URL, and pagination validation. |
| `backend/app/ml/url_features.py` | Extracts URL characteristics and produces URL indicators. |
| `backend/app/ml/email_features.py` | Extracts email metadata/text features and email indicators. |
| `backend/app/ml/predictor.py` | Loads models, calculates phishing probability, and creates explanations. |
| `backend/app/ml/train.py` | Builds the URL and email model artifacts. |
| `backend/app/models.py` | Defines users and scan-history database records. |
| `backend/app/privacy.py` | Creates previews and SHA-256 fingerprints for stored input references. |
| `backend/app/config.py` | Reads environment configuration and applies request limits. |

## Machine-learning pipeline

The training command produces separate model artifacts for URLs and emails.
The predictor loads those artifacts from `MODEL_DIR` when the application
starts:

- URL scans use a Random Forest model over structural URL features.
- Email scans use a text-and-metadata pipeline with Logistic Regression.
- The phishing probability is scaled to a 0-100 integer score.
- Scores map to `low` (0-34), `medium` (35-69), or `high` (70-100).
- Feature indicators and, for emails, flagged links and influential terms are
  returned alongside the score.

If either model is missing, scan endpoints return `503` with
`model_unavailable` rather than producing a misleading result.

## Data model and privacy boundary

`User` records contain an email, a password hash, and creation time. `Scan`
records are linked to one user and contain:

- scan kind (`url` or `email`)
- a short preview
- a SHA-256 input fingerprint
- risk result, indicators, and model version
- creation time

Raw email bodies and complete URLs are not stored in scan history. The
application also analyses URL strings without making outbound requests to the
submitted sites.

## Configuration and deployment

Configuration is supplied through environment variables. Important settings
include `DATABASE_URL`, `JWT_SECRET_KEY`, `MODEL_DIR`, `CORS_ORIGINS`,
`JWT_EXPIRES_MINUTES`, and `RATELIMIT_STORAGE_URI`. The development default is
SQLite; Docker Compose provides PostgreSQL for local use.

The default rate-limit storage is in memory. Production deployments should use
a shared Redis storage URI when running multiple backend workers. Model files
are serialized artifacts and should only be loaded from a trusted training
environment.
