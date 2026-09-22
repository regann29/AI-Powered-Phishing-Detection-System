from app.ml.email_features import extract_email_features, email_indicators
from app.ml.url_features import extract_url_features, parse_url, url_indicators


def ids(url):
    return {i["id"] for i in url_indicators(url)}


def test_parse_registered_domain():
    assert parse_url("https://www.bbc.co.uk/news").registered_domain == "bbc.co.uk"
    assert parse_url("https://login.example.com/x").subdomain == "login"


def test_ip_and_userinfo_flagged():
    assert "ip_host" in ids("http://192.168.1.10/login")
    assert "ip_host" in ids("http://3232235777/login")
    assert "userinfo" in ids("http://paypal.com@evil.xyz/signin")


def test_brand_outside_domain_flagged():
    assert "brand_mismatch" in ids("http://paypal.secure-check.xyz/verify")
    assert "brand_mismatch" not in ids("https://www.paypal.com/signin")


def test_punycode_shortener_and_tld():
    assert "punycode" in ids("http://xn--pypal-4ve.com/")
    assert "shortener" in ids("https://bit.ly/abc123")
    assert "suspicious_tld" in ids("https://free-gift.top/claim")


def test_clean_url_has_no_high_severity():
    found = url_indicators("https://docs.python.org/3/library/json.html")
    assert not [i for i in found if i["severity"] == "high"]


def test_feature_vector_is_numeric_and_stable():
    a = extract_url_features("https://example.com/a")
    b = extract_url_features("https://example.com/a")
    assert a == b and all(isinstance(v, float) for v in a.values())


def test_email_link_mismatch_and_reply_to():
    body = '<html><body><a href="http://evil.top/x">https://www.paypal.com/account</a></body></html>'
    row = extract_email_features("service@gmail.com", "help@other.net", "Account notice", body)
    assert row["link_text_mismatch"] == 1
    assert row["reply_to_mismatch"] == 1
    found, _ = email_indicators(row, body)
    assert {"link_mismatch", "reply_to_mismatch"} <= {i["id"] for i in found}


def test_email_urgency_and_credentials():
    body = "Urgent! Your account will be suspended. Confirm your password and card number immediately."
    row = extract_email_features("a@b.com", "", "Final notice", body)
    assert row["urgency_count"] >= 2 and row["credential_count"] >= 2
