"""Email feature extraction: numeric header/body signals plus cleaned text for TF-IDF."""
from __future__ import annotations

import html
import math
import re

from .url_features import SHORTENERS, parse_url, url_indicators, url_rule_score

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
ANCHOR_RE = re.compile(r"<a\s[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")
SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b.*?</\1>", re.I | re.S)
VISIBLE_DOMAIN_RE = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)

URGENCY_PHRASES = (
    "urgent", "immediately", "asap", "within 24 hours", "within 48 hours", "final notice",
    "last warning", "action required", "suspended", "will expire", "limited time", "act now",
    "verify now", "deactivated", "locked", "unusual activity", "unauthorized",
)
CREDENTIAL_PHRASES = (
    "password", "verify your account", "confirm your identity", "social security", "ssn",
    "credit card", "card number", "bank account", "login credentials", "one-time code",
    "security code", "update your payment", "billing information", "sign in to", "log in to",
)
FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me",
    "protonmail.com", "gmx.com", "mail.com",
}
BRAND_WORDS = ("paypal", "apple", "microsoft", "amazon", "netflix", "bank", "docusign", "irs", "dhl", "fedex")

NUMERIC_FEATURES = [
    "subject_length", "body_length_log", "num_urls", "num_unique_url_domains", "num_ip_urls",
    "num_shortener_urls", "max_url_rule_score", "num_exclamations", "uppercase_ratio",
    "subject_uppercase_ratio", "urgency_count", "credential_count", "has_html", "has_form",
    "link_text_mismatch", "reply_to_mismatch", "sender_free_mail", "brand_with_free_mail",
]


def html_to_text(body: str) -> str:
    without_code = SCRIPT_STYLE_RE.sub(" ", body)
    return html.unescape(TAG_RE.sub(" ", without_code))


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def extract_urls(body: str, limit: int = 50) -> list[str]:
    """URLs from plain text and from anchor hrefs, de-duplicated, capped to keep scans fast."""
    seen: dict[str, None] = {}
    for href, _text in ANCHOR_RE.findall(body):
        if href.lower().startswith(("http://", "https://")):
            seen.setdefault(href.strip(), None)
    for match in URL_RE.findall(body):
        seen.setdefault(match.rstrip(".,;:!?"), None)
    return list(seen)[:limit]


def _link_text_mismatches(body: str) -> int:
    """Count anchors whose visible text shows one domain while the href goes to another."""
    count = 0
    for href, text in ANCHOR_RE.findall(body):
        shown = VISIBLE_DOMAIN_RE.search(TAG_RE.sub("", text))
        if not shown or not href.lower().startswith(("http://", "https://")):
            continue
        shown_domain = parse_url(shown.group(0)).registered_domain
        real_domain = parse_url(href).registered_domain
        if shown_domain and real_domain and shown_domain != real_domain:
            count += 1
    return count


def extract_email_features(sender: str, reply_to: str, subject: str, body: str) -> dict:
    """Return a row with NUMERIC_FEATURES plus a 'text' field for the TF-IDF vectoriser."""
    has_html = bool(re.search(r"<\s*(html|body|a\s|div|table|p\b|br)", body, re.I))
    plain = html_to_text(body) if has_html else body
    lower = f"{subject}\n{plain}".lower()

    urls = extract_urls(body)
    parsed = [parse_url(u) for u in urls]
    sender_domain, reply_domain = _domain(sender), _domain(reply_to)
    letters = [c for c in plain if c.isalpha()]
    subject_letters = [c for c in subject if c.isalpha()]

    row = {
        "subject_length": len(subject),
        "body_length_log": math.log1p(len(plain)),
        "num_urls": len(urls),
        "num_unique_url_domains": len({p.registered_domain for p in parsed}),
        "num_ip_urls": sum(p.is_ip for p in parsed),
        "num_shortener_urls": sum(p.registered_domain in SHORTENERS for p in parsed),
        "max_url_rule_score": max((url_rule_score(u) for u in urls), default=0),
        "num_exclamations": lower.count("!"),
        "uppercase_ratio": sum(c.isupper() for c in letters) / max(len(letters), 1),
        "subject_uppercase_ratio": sum(c.isupper() for c in subject_letters) / max(len(subject_letters), 1),
        "urgency_count": sum(lower.count(p) for p in URGENCY_PHRASES),
        "credential_count": sum(lower.count(p) for p in CREDENTIAL_PHRASES),
        "has_html": int(has_html),
        "has_form": int(bool(re.search(r"<\s*form\b|<\s*input\b", body, re.I))),
        "link_text_mismatch": _link_text_mismatches(body),
        "reply_to_mismatch": int(bool(reply_domain and sender_domain and reply_domain != sender_domain)),
        "sender_free_mail": int(sender_domain in FREE_MAIL_DOMAINS),
        "brand_with_free_mail": int(sender_domain in FREE_MAIL_DOMAINS and any(b in lower for b in BRAND_WORDS)),
    }
    text = URL_RE.sub(" urltoken ", lower)
    row["text"] = re.sub(r"\s+", " ", text)[:20_000]
    return row


def email_indicators(row: dict, body: str) -> tuple[list[dict], list[dict]]:
    """Return (indicators, flagged_links) explaining the numeric signals in plain language."""
    found: list[dict] = []

    def add(indicator_id: str, severity: str, message: str) -> None:
        found.append({"id": indicator_id, "severity": severity, "message": message})

    flagged: list[dict] = []
    for url in extract_urls(body):
        reasons = [i for i in url_indicators(url) if i["severity"] in ("high", "medium")]
        if url_rule_score(url) >= 3 and reasons:
            flagged.append({"host": parse_url(url).host, "reasons": [r["message"] for r in reasons[:3]]})
    flagged = flagged[:5]

    if row["link_text_mismatch"]:
        add("link_mismatch", "high", "A link shows one web address but sends you to a different one.")
    if row["reply_to_mismatch"]:
        add("reply_to_mismatch", "high", "The reply-to address uses a different domain from the sender.")
    if row["brand_with_free_mail"]:
        add("brand_free_mail", "high", "The message mentions a well-known company but comes from a free email service.")
    if row["has_form"]:
        add("embedded_form", "high", "The message contains a form that could collect information directly.")
    if flagged:
        add("risky_links", "high", f"{len(flagged)} link(s) in the message look suspicious.")
    if row["credential_count"] >= 2:
        add("credential_request", "medium", "The message asks for passwords, payment details or identity confirmation.")
    if row["urgency_count"] >= 2:
        add("urgency", "medium", "The message uses urgent or threatening language to push a quick response.")
    if row["num_ip_urls"]:
        add("ip_links", "medium", "The message links to a raw IP address.")
    if row["num_shortener_urls"]:
        add("shortened_links", "medium", "The message contains shortened links that hide their destination.")
    if row["subject_uppercase_ratio"] > 0.6 and row["subject_length"] > 8:
        add("shouting_subject", "low", "The subject line is mostly capital letters.")
    if row["num_exclamations"] >= 3:
        add("exclamations", "low", "The message uses many exclamation marks.")

    order = {"high": 0, "medium": 1, "low": 2}
    found.sort(key=lambda i: order[i["severity"]])
    return found, flagged
