from conftest import register_and_login

PHISH = "http://paypal.secure-login-x7k2.xyz/verify/index.php?id=abc123&token=zzzz"
LEGIT = "https://www.wikipedia.org/wiki/Python"


def test_health(client):
    body = client.get("/api/health").get_json()
    assert body["status"] == "ok" and body["models_ready"] is True


def test_scan_requires_auth(client):
    assert client.post("/api/scan/url", json={"url": LEGIT}).status_code == 401
    assert client.get("/api/scans").status_code == 401


def test_register_validation(client):
    assert client.post("/api/auth/register", json={"email": "nope", "password": "correct-horse-42"}).status_code == 400
    assert client.post("/api/auth/register", json={"email": "a@b.com", "password": "short1"}).status_code == 400
    assert client.post("/api/auth/register", json={"email": "a@b.com", "password": "onlyletterspassword"}).status_code == 400
    assert client.post("/api/auth/register", data="not json").status_code == 400


def test_duplicate_and_bad_login(client):
    creds = {"email": "dup@example.com", "password": "correct-horse-42"}
    assert client.post("/api/auth/register", json=creds).status_code == 201
    assert client.post("/api/auth/register", json=creds).status_code == 409
    bad = client.post("/api/auth/login", json={**creds, "password": "wrong-password-1"})
    unknown = client.post("/api/auth/login", json={"email": "ghost@example.com", "password": "wrong-password-1"})
    assert bad.status_code == unknown.status_code == 401
    assert bad.get_json() == unknown.get_json()


def test_url_scan_ranks_phishing_above_legit(client, auth):
    phish = client.post("/api/scan/url", json={"url": PHISH}, headers=auth).get_json()
    legit = client.post("/api/scan/url", json={"url": LEGIT}, headers=auth).get_json()
    assert phish["risk_score"] > legit["risk_score"]
    assert phish["risk_level"] == "high" and legit["risk_level"] == "low"
    assert any(i["id"] == "brand_mismatch" for i in phish["indicators"])


def test_url_validation(client, auth):
    for bad in ["", "ftp://example.com/x", "http://exa mple.com", "javascript:alert(1)", "http://", 123]:
        res = client.post("/api/scan/url", json={"url": bad}, headers=auth)
        assert res.status_code == 400, bad
    assert client.post("/api/scan/url", json={"url": "x" * 3000}, headers=auth).status_code == 400
    assert client.post("/api/scan/url", json={"url": "example.com/path"}, headers=auth).status_code == 201


def test_email_scan(client, auth):
    body = ("Dear customer, we detected unusual activity. Your account will be suspended within 24 hours "
            "unless you verify your identity immediately and confirm your password.\n" + PHISH)
    res = client.post("/api/scan/email", json={"sender": "security@gmail.com", "subject": "URGENT: account suspended", "body": body}, headers=auth)
    data = res.get_json()
    assert res.status_code == 201
    assert data["risk_level"] == "high"
    assert data["top_terms"] and data["indicators"]

    ok = client.post("/api/scan/email", json={"sender": "alice@company.com", "subject": "Meeting notes",
                     "body": "Hi team, attached are the notes from Tuesday's meeting. Thanks."}, headers=auth).get_json()
    assert ok["risk_score"] < data["risk_score"]


def test_email_body_required_and_capped(client, auth):
    assert client.post("/api/scan/email", json={"subject": "hi"}, headers=auth).status_code == 400
    assert client.post("/api/scan/email", json={"body": "x" * 60_000}, headers=auth).status_code in (400, 413)


def test_stored_scan_does_not_keep_query_or_body(client, auth):
    client.post("/api/scan/url", json={"url": PHISH}, headers=auth)
    secret = "call me on 555 123 4567 or mail bob@example.com"
    client.post("/api/scan/email", json={"subject": secret, "body": "Please confirm your password now. " + secret}, headers=auth)
    items = client.get("/api/scans", headers=auth).get_json()["items"]
    previews = " ".join(i["preview"] for i in items)
    assert "token=zzzz" not in previews and "?" not in previews
    assert "bob@example.com" not in previews and "4567" not in previews


def test_history_is_private_and_deletable(client):
    a = register_and_login(client, "a@example.com")
    b = register_and_login(client, "b@example.com")
    scan_id = client.post("/api/scan/url", json={"url": LEGIT}, headers=a).get_json()["id"]

    assert client.get(f"/api/scans/{scan_id}", headers=b).status_code == 404
    assert client.delete(f"/api/scans/{scan_id}", headers=b).status_code == 404
    assert client.get("/api/scans", headers=b).get_json()["total"] == 0

    assert client.get(f"/api/scans/{scan_id}", headers=a).status_code == 200
    assert client.delete(f"/api/scans/{scan_id}", headers=a).status_code == 204
    assert client.get("/api/scans", headers=a).get_json()["total"] == 0


def test_pagination_validation(client, auth):
    assert client.get("/api/scans?page=abc", headers=auth).status_code == 400
    assert client.get("/api/scans?per_page=0", headers=auth).status_code == 400
    assert client.get("/api/scans?per_page=500", headers=auth).status_code == 200


def test_security_headers(client):
    res = client.get("/api/health")
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"


def test_unknown_route_returns_json(client):
    res = client.get("/api/nope")
    assert res.status_code == 404 and res.get_json()["error"]["code"] == "not_found"
