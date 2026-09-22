"""Helpers that keep sensitive content out of the database."""
import hashlib
import re
from urllib.parse import urlsplit

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_LONG_NUMBER = re.compile(r"\d[\d\s-]{5,}\d")


def fingerprint(*parts: str) -> str:
    return hashlib.sha256("\n".join(parts).encode("utf-8", "replace")).hexdigest()


def redact(text: str) -> str:
    """Mask email addresses and long digit runs (card, phone, ID numbers)."""
    return _LONG_NUMBER.sub("[number]", _EMAIL.sub("[email]", text))


def url_preview(url: str, limit: int = 200) -> str:
    """Scheme, host and path only. Query strings and fragments often carry tokens."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return f"{parts.scheme}://{host}{parts.path}"[:limit]


def email_preview(subject: str, limit: int = 120) -> str:
    return redact(subject or "(no subject)")[:limit]
