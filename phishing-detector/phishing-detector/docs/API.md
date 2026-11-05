# API reference

The Flask backend exposes JSON endpoints under `/api`. Unless noted otherwise,
successful write operations return JSON. Errors use the same shape:

```json
{
  "error": {
    "code": "validation_error",
    "message": "'url' is required.",
    "field": "url"
  }
}
```

## Health

### `GET /api/health`

Returns service and model status. This endpoint does not require
authentication.

```json
{
  "status": "ok",
  "models_ready": true,
  "model_version": "demo"
}
```

## Authentication

### `POST /api/auth/register`

Creates an account. Passwords must be at least 10 characters and contain a
letter and a digit.

```json
{
  "email": "person@example.com",
  "password": "correct-horse-7"
}
```

Returns `201 Created`:

```json
{
  "id": 1,
  "email": "person@example.com"
}
```

### `POST /api/auth/login`

Accepts the same credentials and returns a bearer token:

```json
{
  "access_token": "JWT_TOKEN",
  "user": {
    "id": 1,
    "email": "person@example.com"
  }
}
```

Send the token on protected endpoints:

```http
Authorization: Bearer JWT_TOKEN
```

## Scanning

### `POST /api/scan/url`

Requires authentication. Accepts an HTTP or HTTPS URL. The server analyses the
address as text and does not visit it.

```json
{
  "url": "https://example.com/login"
}
```

Returns `201 Created` with a scan result:

```json
{
  "id": 12,
  "kind": "url",
  "preview": "https://example.com/login",
  "risk_score": 18,
  "risk_level": "low",
  "verdict": "Likely legitimate",
  "indicators": [],
  "model_version": "demo",
  "created_at": "2026-01-01T12:00:00+00:00"
}
```

### `POST /api/scan/email`

Requires authentication. `body` is required; the other fields are optional.

```json
{
  "sender": "alerts@example.com",
  "reply_to": "reply@example.com",
  "subject": "Please verify your account",
  "body": "Your account requires attention."
}
```

The result has the same common fields as a URL scan and can also include
`top_terms` and `flagged_links`.

## Scan history

All history endpoints require authentication and are scoped to the current
user.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/scans?page=1&per_page=20` | List scans, newest first. |
| `GET` | `/api/scans/<scan_id>` | Get one owned scan. |
| `DELETE` | `/api/scans/<scan_id>` | Delete one owned scan. |
| `DELETE` | `/api/scans` | Delete all scans for the current user. |

The list response contains `items`, `page`, `per_page`, and `total`. A
successful single-delete returns `204 No Content`; deleting all scans returns
the number deleted.

## Status codes

- `200` - successful read or login
- `201` - account or scan created
- `204` - scan deleted
- `400` - invalid JSON or input
- `401` - missing/invalid authentication or account
- `404` - resource not found or not owned by the current user
- `409` - email address already registered
- `413` - request body is too large
- `429` - rate limit exceeded
- `503` - models are not ready
- `500` - unexpected server error
