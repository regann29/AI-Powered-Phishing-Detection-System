"""Input validation. Every request body is checked here before use."""
import re
from urllib.parse import urlsplit

from flask import request


class ValidationError(Exception):
    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.message = message
        self.field = field


EMAIL_RE = re.compile(r"^[^@\s<>]{1,64}@[^@\s<>]{1,255}\.[^@\s<>]{2,}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

MAX_URL_LENGTH = 2048
MAX_SUBJECT_LENGTH = 300
MAX_BODY_LENGTH = 50_000
MAX_ADDRESS_LENGTH = 320


def json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object.")
    return data


def _text(data: dict, field: str, max_len: int, required: bool = True, multiline: bool = False) -> str:
    value = data.get(field)
    if value is None or value == "":
        if required:
            raise ValidationError(f"'{field}' is required.", field)
        return ""
    if not isinstance(value, str):
        raise ValidationError(f"'{field}' must be a string.", field)
    if len(value) > max_len:
        raise ValidationError(f"'{field}' must be at most {max_len} characters.", field)
    if _CONTROL_CHARS.search(value):
        raise ValidationError(f"'{field}' contains invalid control characters.", field)
    if not multiline and ("\n" in value or "\r" in value):
        raise ValidationError(f"'{field}' must be a single line.", field)
    return value.strip()


def _email_address(data: dict, field: str, required: bool) -> str:
    value = _text(data, field, MAX_ADDRESS_LENGTH, required=required)
    if value and not EMAIL_RE.match(value):
        raise ValidationError(f"'{field}' must be a valid email address.", field)
    return value.lower()


def validate_credentials(data: dict, check_strength: bool = False) -> tuple[str, str]:
    email = _email_address(data, "email", required=True)
    password = data.get("password")
    if not isinstance(password, str) or not password:
        raise ValidationError("'password' is required.", "password")
    if len(password) > 128:
        raise ValidationError("'password' must be at most 128 characters.", "password")
    if check_strength:
        if len(password) < 10:
            raise ValidationError("Password must be at least 10 characters.", "password")
        if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
            raise ValidationError("Password must contain at least one letter and one digit.", "password")
    return email, password


def validate_url_payload(data: dict) -> str:
    raw = _text(data, "url", MAX_URL_LENGTH)
    if re.search(r"\s", raw):
        raise ValidationError("'url' must not contain spaces.", "url")
    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        parts.port  # raises ValueError for an invalid port
    except ValueError:
        raise ValidationError("'url' is not a valid URL.", "url")
    if parts.scheme not in ("http", "https"):
        raise ValidationError("Only http and https URLs can be analysed.", "url")
    if not hostname or "." not in hostname and ":" not in hostname:
        raise ValidationError("'url' must include a valid host name.", "url")
    return candidate


def validate_email_payload(data: dict) -> dict:
    return {
        "sender": _email_address(data, "sender", required=False),
        "reply_to": _email_address(data, "reply_to", required=False),
        "subject": _text(data, "subject", MAX_SUBJECT_LENGTH, required=False),
        "body": _text(data, "body", MAX_BODY_LENGTH, required=True, multiline=True),
    }


def positive_int(value: str | None, default: int, maximum: int, field: str) -> int:
    if value is None:
        return default
    try:
        number = int(value)
    except ValueError:
        raise ValidationError(f"'{field}' must be an integer.", field)
    if number < 1:
        raise ValidationError(f"'{field}' must be at least 1.", field)
    return min(number, maximum)
