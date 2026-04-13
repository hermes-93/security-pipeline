import os
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only")

from src.main import app

client = TestClient(app)


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_ready():
    r = client.get("/ready")
    assert r.status_code == 200


def test_login_success():
    r = client.post("/auth/token", json={"username": "admin", "password": "changeme"})
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_login_wrong_password():
    r = client.post("/auth/token", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_items_requires_auth():
    r = client.get("/items")
    assert r.status_code == 403


def test_items_with_token():
    token = client.post(
        "/auth/token", json={"username": "admin", "password": "changeme"}
    ).json()["access_token"]
    r = client.get("/items", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_hash_demo():
    r = client.get("/hash-demo", params={"data": "hello"})
    assert r.status_code == 200
    assert len(r.json()["sha256"]) == 64
