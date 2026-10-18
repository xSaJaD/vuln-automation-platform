"""اختبارات Phase 17 — RBAC (أدوار admin/viewer عبر API keys)."""

from api.services.auth import generate_api_key, hash_key, verify_key


def test_key_hash_and_verify(db_session):
    from api.models.api_key import ApiKey

    raw = generate_api_key()
    db_session.add(ApiKey(key_hash=hash_key(raw), role="admin", label="root"))
    db_session.commit()

    found = verify_key(db_session, raw)
    assert found is not None and found.role == "admin"
    assert verify_key(db_session, "iqs_wrong") is None


def test_auth_disabled_allows_all(client):
    # auth_enabled=False افتراضيًا (conftest لا يغيّره) — لا حاجة لمفتاح.
    assert client.get("/programs").status_code == 200


def test_rbac_enforced_when_enabled(client, db_session, monkeypatch):
    from api.config import settings

    monkeypatch.setattr(settings, "auth_enabled", True)

    # bootstrap: إنشاء أول مفتاح (admin) بدون مصادقة
    r = client.post("/auth/keys", json={"role": "admin", "label": "root"})
    assert r.status_code == 201
    admin_key = r.json()["api_key"]
    assert admin_key.startswith("iqs_")

    # إنشاء مفتاح viewer (يتطلب admin الآن)
    r = client.post("/auth/keys", json={"role": "viewer"}, headers={"X-API-Key": admin_key})
    assert r.status_code == 201
    viewer_key = r.json()["api_key"]

    # بدون مفتاح → 401
    assert client.get("/programs").status_code == 401

    # viewer يقرأ → مسموح
    assert client.get("/programs", headers={"X-API-Key": viewer_key}).status_code == 200

    # viewer يكتب → 403
    w = client.post("/programs", json={"name": "x", "handle": "x"}, headers={"X-API-Key": viewer_key})
    assert w.status_code == 403

    # admin يكتب → مسموح
    a = client.post("/programs", json={"name": "y", "handle": "y"}, headers={"X-API-Key": admin_key})
    assert a.status_code == 201


def test_second_key_creation_needs_admin_when_enabled(client, db_session, monkeypatch):
    from api.config import settings

    monkeypatch.setattr(settings, "auth_enabled", True)
    # أول مفتاح bootstrap
    client.post("/auth/keys", json={"role": "admin"})
    # محاولة إنشاء مفتاح آخر بدون مصادقة → 401 (لم يعد bootstrap)
    assert client.post("/auth/keys", json={"role": "viewer"}).status_code == 401
