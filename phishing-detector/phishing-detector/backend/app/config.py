"""Application configuration. Secrets come from environment variables only."""
import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _database_url() -> str:
    url = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'dev.db'}")
    # Some hosts still hand out the legacy "postgres://" scheme.
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


class Config:
    APP_ENV = os.getenv("APP_ENV", "development")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")

    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    MODEL_DIR = os.getenv("MODEL_DIR", str(BASE_DIR / "models"))

    # Reject oversized request bodies before they reach any parsing code.
    MAX_CONTENT_LENGTH = 256 * 1024

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(os.getenv("JWT_EXPIRES_MINUTES", "30")))

    CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()]

    # Use redis://... in production so limits are shared across workers.
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_ENABLED = True


class TestConfig(Config):
    TESTING = True
    APP_ENV = "testing"
    JWT_SECRET_KEY = "test-only-secret-key-that-is-long-enough-for-hs256"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    RATELIMIT_ENABLED = False
