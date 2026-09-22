import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app  # noqa: E402
from app.config import TestConfig  # noqa: E402
from app.ml.train import train_all_demo  # noqa: E402


@pytest.fixture(scope="session")
def model_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("models")
    train_all_demo(out, size=1200)
    return out


@pytest.fixture()
def app(model_dir):
    class Cfg(TestConfig):
        MODEL_DIR = str(model_dir)

    return create_app(Cfg)


@pytest.fixture()
def client(app):
    return app.test_client()


def register_and_login(client, email="user@example.com", password="correct-horse-42"):
    client.post("/api/auth/register", json={"email": email, "password": password})
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    return {"Authorization": f"Bearer {res.get_json()['access_token']}"}


@pytest.fixture()
def auth(client):
    return register_and_login(client)
