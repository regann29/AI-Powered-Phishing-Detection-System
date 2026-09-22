"""Synthetic demo data so the project runs end to end without downloading a dataset.

This data is generated from hand-written patterns. A model trained on it will
look very accurate and still generalise poorly. For real use, train on
labelled data such as PhishTank/OpenPhish URLs and a phishing email corpus
(see README, "Training on real data").
"""
from __future__ import annotations

import random
import string

import pandas as pd

LEGIT_DOMAINS = [
    "wikipedia.org", "github.com", "python.org", "stackoverflow.com", "nytimes.com", "bbc.co.uk",
    "mozilla.org", "openstreetmap.org", "arxiv.org", "nasa.gov", "who.int", "harvard.edu",
    "medium.com", "reddit.com", "npmjs.com", "docs.python.org", "kubernetes.io", "cloudflare.com",
    "paypal.com", "apple.com", "microsoft.com", "amazon.com", "google.com", "netflix.com",
    "linkedin.com", "dropbox.com", "coursera.org", "khanacademy.org", "imdb.com", "ubuntu.com",
]
LEGIT_PATHS = [
    "", "about", "docs/getting-started", "blog/2024/release-notes", "wiki/Machine_learning",
    "help/contact", "products/pricing", "search?q=climate+data", "news/technology", "login",
    "signin", "account/settings", "support/articles/1234567", "download", "careers/engineering",
    "questions/12345/how-to-parse-json", "user/profile", "checkout/cart",
]
WORDS = ["secure", "verify", "account", "login", "update", "billing", "support", "confirm", "wallet", "signin"]
BAD_TLDS = ["xyz", "top", "tk", "ml", "click", "icu", "work", "support", "buzz", "cam"]
MIXED_TLDS = ["com", "net", "info", "online", "site", "co"]
BRANDS = ["paypal", "apple", "microsoft", "amazon", "netflix", "google", "facebook", "dropbox", "docusign", "coinbase"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly"]


def _rand(rng: random.Random, low: int, high: int) -> str:
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(low, high)))


def legit_url(rng: random.Random) -> str:
    if rng.random() < 0.06:
        return f"https://{rng.choice(SHORTENERS)}/{_rand(rng, 6, 8)}"
    domain = rng.choice(LEGIT_DOMAINS)
    sub = rng.choice(["", "", "www.", "docs.", "support.", "blog."]) if domain.count(".") == 1 else ""
    scheme = "http" if rng.random() < 0.05 else "https"
    path = rng.choice(LEGIT_PATHS)
    if rng.random() < 0.1:
        path += f"{'&' if '?' in path else '?'}utm_source={_rand(rng, 4, 8)}&ref={_rand(rng, 4, 8)}"
    return f"{scheme}://{sub}{domain}/{path}" if path else f"{scheme}://{sub}{domain}"


def phishing_url(rng: random.Random) -> str:
    brand, word = rng.choice(BRANDS), rng.choice(WORDS)
    junk, tld = _rand(rng, 5, 12), rng.choice(BAD_TLDS + MIXED_TLDS)
    ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
    kind = rng.randint(0, 9)
    if kind == 0:
        return f"http://{brand}.{word}-{junk}.{tld}/{word}/index.php?id={junk}"
    if kind == 1:
        return f"http://{ip}/{brand}/{word}.html"
    if kind == 2:
        return f"https://{brand}-{word}.{tld}/{word}?session={junk}&token={_rand(rng, 16, 24)}"
    if kind == 3:
        return f"http://{brand}.com@{junk}.{tld}/{word}"
    if kind == 4:
        return f"https://{word}.{brand}.{junk}.{tld}/{word}/login"
    if kind == 5:
        return f"http://xn--{brand}-{junk}.com/{word}"
    if kind == 6:
        return f"https://{junk}.{tld}/{brand}/{word}/verify?email=user%40example.com"
    if kind == 7:
        return f"https://{rng.choice(SHORTENERS)}/{_rand(rng, 6, 8)}"
    if kind == 8:  # cleaner-looking domain, harder to catch
        return f"https://{word}-{brand}{rng.randint(1, 99)}.{rng.choice(MIXED_TLDS)}/{word}"
    return f"http://{junk}.{rng.choice(BAD_TLDS)}:{rng.choice([8080, 8443, 2083])}/{word}/{_rand(rng, 6, 10)}.php"


def make_url_frame(size: int = 3000, seed: int = 42) -> pd.DataFrame:
    rng = random.Random(seed)
    rows = [(legit_url(rng), 0) for _ in range(size // 2)] + [(phishing_url(rng), 1) for _ in range(size // 2)]
    rng.shuffle(rows)
    return pd.DataFrame(rows, columns=["url", "label"]).drop_duplicates("url").reset_index(drop=True)


_LEGIT_SUBJECTS = [
    "Meeting notes from Tuesday", "Your receipt from Blue Bottle", "Quarterly planning agenda",
    "Re: project timeline", "Weekly team update", "Invoice 2041 attached", "Lunch on Friday?",
    "Password reset requested", "Your order has shipped", "Conference schedule and travel details",
]
_LEGIT_BODIES = [
    "Hi team, attached are the notes from Tuesday's meeting. Please review the action items and let me know if anything is missing. Thanks.",
    "Thanks for your purchase. Your order will arrive in 3 to 5 business days. You can track it from your account page. Contact us if you have questions.",
    "Here is the agenda for next week's planning session. We will cover the roadmap, hiring, and budget. Bring your questions and updates.",
    "Just a reminder that the report is due on Friday. I have shared the draft in our shared folder. Let me know what you think about section three.",
    "You asked to reset your password. If this was you, use the link below within an hour. If not, you can ignore this message and your password will stay the same.",
    "Hello, the invoice for last month is attached. Payment is due within 30 days. Please reach out to accounting if you have any questions.",
]
_PHISH_SUBJECTS = [
    "URGENT: Your account has been suspended", "Action required: verify your identity", "Security alert: unusual activity detected",
    "Final notice: payment failed", "You have won a prize", "Confirm your password now", "Your mailbox is almost full",
    "Unauthorized login attempt blocked", "Invoice overdue: immediate payment needed", "Update your billing information",
]
_PHISH_BODIES = [
    "Dear customer, we detected unusual activity on your account. Your account will be suspended within 24 hours unless you verify your identity immediately. Click the link below to confirm your password and card number.",
    "Action required! Your payment failed and your subscription has been locked. Update your billing information now to avoid deactivation. Failure to act will result in permanent closure.",
    "Security notice: someone tried to sign in to your account from a new device. If this was not you, log in to secure your account right away. This link will expire soon.",
    "Congratulations, you have been selected to receive a reward. Confirm your bank account details today to claim it. Offer is for a limited time only, act now!",
    "Your mailbox storage is full and incoming messages are being blocked. Verify your login credentials to restore service. Your account will be deleted if you ignore this final notice.",
    "We could not deliver your parcel. Confirm your address and pay the small customs fee immediately using the link below.",
]
_LEGIT_SENDERS = ["alice@company.com", "billing@shop.example.com", "team@university.edu", "no-reply@service.example.org"]
_FREE_SENDERS = ["support.team@gmail.com", "security.notice@outlook.com", "helpdesk@yahoo.com"]


def make_email_frame(size: int = 1200, seed: int = 7) -> pd.DataFrame:
    rng = random.Random(seed)
    rows = []
    for i in range(size):
        phishing = i % 2 == 1
        if phishing:
            subject, body = rng.choice(_PHISH_SUBJECTS), rng.choice(_PHISH_BODIES)
            sender = rng.choice(_FREE_SENDERS + _LEGIT_SENDERS)
            reply_to = rng.choice(["", "", "collect@mail-relay.example.net", "refund@gmail.com"])
            link = phishing_url(rng)
            if rng.random() < 0.3:
                shown = f"https://www.{rng.choice(BRANDS)}.com/account"
                body = f"<html><body><p>{body}</p><a href=\"{link}\">{shown}</a></body></html>"
            elif rng.random() < 0.8:
                body = f"{body}\n{link}"
            if rng.random() < 0.25:  # some phishing is short and polite
                body = "Please review the attached document and sign in to confirm your details.\n" + link
        else:
            subject, body = rng.choice(_LEGIT_SUBJECTS), rng.choice(_LEGIT_BODIES)
            sender = rng.choice(_LEGIT_SENDERS + _FREE_SENDERS[:1])
            reply_to = ""
            if rng.random() < 0.5:
                body = f"{body}\nSee https://{rng.choice(LEGIT_DOMAINS)}/{rng.choice(LEGIT_PATHS)}"
            if rng.random() < 0.1:
                subject = "URGENT: " + subject  # legitimate mail can also be urgent
        rows.append((sender, reply_to, subject, body, int(phishing)))
    return pd.DataFrame(rows, columns=["sender", "reply_to", "subject", "body", "label"])
