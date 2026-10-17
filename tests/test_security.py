"""اختبارات Phase 11 — التشفير، تحديد المعدّل، واعتمادات grey-box المُشفّرة."""

import pytest
from cryptography.fernet import InvalidToken

from api.services.crypto import FieldCipher, generate_key
from api.services.ratelimit import RateLimiter

# ── التشفير ──

def test_cipher_roundtrip():
    cipher = FieldCipher(generate_key())
    token = cipher.encrypt("SuperSecret123")
    assert token != "SuperSecret123"
    assert cipher.decrypt(token) == "SuperSecret123"


def test_wrong_key_cannot_decrypt():
    t = FieldCipher(generate_key()).encrypt("x")
    with pytest.raises(InvalidToken):
        FieldCipher(generate_key()).decrypt(t)


# ── تحديد المعدّل ──

def test_ratelimit_allows_then_blocks():
    rl = RateLimiter(limit=3, window=60)
    assert [rl.allow("ip", now=0) for _ in range(3)] == [True, True, True]
    assert rl.allow("ip", now=0) is False


def test_ratelimit_window_resets():
    rl = RateLimiter(limit=1, window=60)
    assert rl.allow("ip", now=0) is True
    assert rl.allow("ip", now=30) is False
    assert rl.allow("ip", now=61) is True


def test_ratelimit_per_key():
    rl = RateLimiter(limit=1, window=60)
    assert rl.allow("a", now=0) is True
    assert rl.allow("b", now=0) is True  # مفتاح مختلف لا يتأثر


# ── اعتمادات مُشفّرة عبر الـ API ──

def test_credential_stored_encrypted(client, db_session, monkeypatch):
    from api.config import settings
    from api.models.credential import Credential

    monkeypatch.setattr(settings, "field_encryption_key", generate_key())
    pid = client.post("/programs", json={"name": "A", "handle": "a"}).json()["id"]

    r = client.post(f"/programs/{pid}/credentials", json={"label": "h1-token", "secret": "TOP-SECRET-9"})
    assert r.status_code == 201
    assert "secret" not in r.json()
    assert "TOP-SECRET-9" not in r.text  # السر لا يُعاد

    cred = db_session.query(Credential).first()
    assert cred.secret_encrypted != "TOP-SECRET-9"
    assert "TOP-SECRET-9" not in cred.secret_encrypted  # مُخزَّن مُشفّرًا

    listed = client.get(f"/programs/{pid}/credentials").json()
    assert listed[0]["label"] == "h1-token"
    assert "secret" not in listed[0]


def test_credential_requires_encryption_key(client, db_session, monkeypatch):
    from api.config import settings

    monkeypatch.setattr(settings, "field_encryption_key", "")
    pid = client.post("/programs", json={"name": "B", "handle": "b"}).json()["id"]

    r = client.post(f"/programs/{pid}/credentials", json={"label": "x", "secret": "y"})
    assert r.status_code == 503  # لا تخزين بدون مفتاح
