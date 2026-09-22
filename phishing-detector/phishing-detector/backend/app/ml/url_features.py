"""Lexical URL features and human-readable security indicators.

Nothing here makes a network request. The URL is only parsed as text, so
scanning a hostile link cannot trigger it or leak the analyst's address.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work",
    "support", "rest", "icu", "buzz", "cam", "monster", "loan", "download", "review", "stream",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc",
}
SENSITIVE_WORDS = (
    "login", "signin", "verify", "account", "update", "secure", "banking", "confirm", "password",
    "wallet", "billing", "suspend", "unlock", "recover", "authenticate", "validate", "webscr",
)
BRANDS = (
    "paypal", "apple", "microsoft", "amazon", "netflix", "google", "facebook", "instagram",
    "dropbox", "docusign", "chase", "wellsfargo", "bankofamerica", "binance", "coinbase",
    "office365", "outlook", "linkedin", "whatsapp", "telegram",
)
# Suffixes with two labels, so "bbc.co.uk" is treated as one registered domain.
MULTIPART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "co.in", "com.br",
    "co.nz", "com.np", "com.cn", "co.za",
}

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length", "num_dots", "num_hyphens_host",
    "num_underscores", "num_slashes", "num_query_params", "num_percent", "num_digits",
    "digit_ratio", "num_subdomains", "is_ip_host", "uses_https", "has_punycode",
    "suspicious_tld", "is_shortener", "has_userinfo", "has_nonstandard_port",
    "sensitive_word_count", "brand_outside_domain", "host_entropy", "longest_host_label",
    "has_double_slash_in_path", "path_depth",
]

_NUMERIC_HOST = re.compile(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*")


@dataclass
class ParsedURL:
    url: str
    scheme: str
    netloc: str
    host: str
    port: int | None
    path: str
    query: str
    subdomain: str
    registered_domain: str
    tld: str
    is_ip: bool


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # Covers decimal/hex forms such as http://3232235777/ or http://0xC0.0xA8.1.1/
        return bool(_NUMERIC_HOST.fullmatch(host))


def parse_url(raw: str) -> ParsedURL:
    url = raw.strip()
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        port = None
    is_ip = _is_ip(host)
    labels = host.split(".") if host and not is_ip else []
    if len(labels) < 2:
        subdomain, registered, tld = "", host, labels[-1] if labels else ""
    else:
        suffix_len = 2 if ".".join(labels[-2:]) in MULTIPART_SUFFIXES and len(labels) > 2 else 1
        registered = ".".join(labels[-(suffix_len + 1):])
        subdomain = ".".join(labels[: -(suffix_len + 1)])
        tld = labels[-1]
    return ParsedURL(url, parts.scheme.lower(), parts.netloc, host, port, parts.path, parts.query,
                     subdomain, registered, tld, is_ip)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _brand_outside_domain(p: ParsedURL) -> str:
    """Return a brand that appears in the subdomain, path or query but not in the registered domain."""
    if p.is_ip:
        rest = f"{p.path} {p.query}".lower()
    else:
        rest = f"{p.subdomain} {p.path} {p.query}".lower()
    own = p.registered_domain.lower()
    for brand in BRANDS:
        if brand in rest and brand not in own:
            return brand
    # "paypal.com@evil.xyz": brand in the user-info part of the authority.
    if "@" in p.netloc:
        userinfo = p.netloc.rsplit("@", 1)[0].lower()
        for brand in BRANDS:
            if brand in userinfo and brand not in own:
                return brand
    return ""


def extract_url_features(raw: str) -> dict[str, float]:
    p = parse_url(raw)
    url, host = p.url, p.host
    lower = url.lower()
    digits = sum(ch.isdigit() for ch in url)
    labels = host.split(".") if host else [""]
    features = {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(p.path),
        "query_length": len(p.query),
        "num_dots": url.count("."),
        "num_hyphens_host": host.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_query_params": (p.query.count("&") + 1) if p.query else 0,
        "num_percent": url.count("%"),
        "num_digits": digits,
        "digit_ratio": digits / max(len(url), 1),
        "num_subdomains": len([s for s in p.subdomain.split(".") if s]) if p.subdomain else 0,
        "is_ip_host": int(p.is_ip),
        "uses_https": int(p.scheme == "https"),
        "has_punycode": int("xn--" in host),
        "suspicious_tld": int(p.tld in SUSPICIOUS_TLDS),
        "is_shortener": int(p.registered_domain in SHORTENERS),
        "has_userinfo": int("@" in p.netloc),
        "has_nonstandard_port": int(p.port not in (None, 80, 443)),
        "sensitive_word_count": sum(lower.count(w) for w in SENSITIVE_WORDS),
        "brand_outside_domain": int(bool(_brand_outside_domain(p))),
        "host_entropy": _entropy(host),
        "longest_host_label": max(len(label) for label in labels),
        "has_double_slash_in_path": int("//" in p.path),
        "path_depth": len([seg for seg in p.path.split("/") if seg]),
    }
    return {name: float(features[name]) for name in FEATURE_NAMES}


_SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1}


def url_indicators(raw: str) -> list[dict]:
    """Plain-language reasons a URL looks risky, ordered from most to least serious."""
    p = parse_url(raw)
    f = extract_url_features(raw)
    found: list[dict] = []

    def add(indicator_id: str, severity: str, message: str) -> None:
        found.append({"id": indicator_id, "severity": severity, "message": message})

    if f["is_ip_host"]:
        add("ip_host", "high", "The link points to a raw IP address instead of a domain name.")
    if f["has_userinfo"]:
        add("userinfo", "high", "The link contains an '@' before the host, a trick used to disguise the real destination.")
    if f["has_punycode"]:
        add("punycode", "high", "The domain uses punycode (xn--), which can imitate look-alike characters.")
    brand = _brand_outside_domain(p)
    if brand:
        add("brand_mismatch", "high",
            f"The name '{brand}' appears in the link, but the real domain is {p.registered_domain or p.host}.")
    if f["is_shortener"]:
        add("shortener", "medium", "A link shortener hides the final destination.")
    if f["suspicious_tld"]:
        add("suspicious_tld", "medium", f"The '.{p.tld}' ending is frequently used for throwaway domains.")
    if f["num_subdomains"] >= 3:
        add("many_subdomains", "medium", f"The host has {int(f['num_subdomains'])} subdomain levels, which can bury the real domain.")
    if f["num_hyphens_host"] >= 2:
        add("hyphenated_host", "medium", "The domain name contains several hyphens.")
    if f["has_nonstandard_port"]:
        add("odd_port", "medium", f"The link uses an unusual port ({p.port}).")
    if f["sensitive_word_count"] >= 2:
        add("sensitive_words", "medium", "The link contains several account or login words such as 'verify' or 'secure'.")
    if not f["uses_https"] and not p.is_ip:
        add("no_https", "low", "The link does not use HTTPS.")
    if f["url_length"] > 100:
        add("long_url", "low", f"The link is unusually long ({int(f['url_length'])} characters).")
    if f["num_percent"] >= 3:
        add("encoded_chars", "low", "The link contains many percent-encoded characters.")
    if f["host_entropy"] > 3.7 and f["host_length"] > 15 and not p.is_ip:
        add("random_host", "low", "The domain name looks randomly generated.")

    found.sort(key=lambda i: -_SEVERITY_WEIGHT[i["severity"]])
    return found


def url_rule_score(raw: str) -> int:
    return sum(_SEVERITY_WEIGHT[i["severity"]] for i in url_indicators(raw))
