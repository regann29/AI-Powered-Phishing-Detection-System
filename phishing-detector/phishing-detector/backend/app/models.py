from datetime import datetime, timezone

from .extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    # SQLite drops tzinfo on read; every timestamp we store is UTC.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    scans = db.relationship("Scan", backref="user", cascade="all, delete-orphan")


class Scan(db.Model):
    """One analysis result.

    Raw email bodies and full URLs are never stored. We keep a SHA-256 of the
    input (to spot repeats), a short redacted preview, and the model output.
    """

    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = db.Column(db.String(10), nullable=False)  # "url" or "email"
    input_preview = db.Column(db.String(300), nullable=False)
    input_hash = db.Column(db.String(64), nullable=False, index=True)
    risk_score = db.Column(db.SmallInteger, nullable=False)
    risk_level = db.Column(db.String(10), nullable=False)
    verdict = db.Column(db.String(40), nullable=False)
    indicators = db.Column(db.JSON, nullable=False, default=list)
    details = db.Column(db.JSON, nullable=False, default=dict)
    model_version = db.Column(db.String(40), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "preview": self.input_preview,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "verdict": self.verdict,
            "indicators": self.indicators,
            **(self.details or {}),
            "model_version": self.model_version,
            "created_at": _iso(self.created_at),
        }
