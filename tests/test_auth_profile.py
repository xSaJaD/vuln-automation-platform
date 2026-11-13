"""اختبارات ملف المصادقة الدائم — تخزين مشفّر + تحميل للعامل + CRUD عبر الـ API."""

import pytest

from api.config import settings
from api.services.auth_loader import load_login_config
from api.services.crypto import generate_key


@pytest.fixture
def enc_key():
    """يفعّل التشفير أثناء الاختبار (مفتاح Fernet مؤقّت)."""
    old = settings.field_encryption_key
    settings.field_encryption_key = generate_key()
    yield
    settings.field_encryption_key = old


def _program(client):
    return client.post("/programs", json={"name": "DVWA", "handle": "dvwa"}).json()["id"]


def test_upsert_and_get_profile_hides_password(client, enc_key):
    pid = _program(client)
    r = client.put(
        f"/programs/{pid}/auth",
        json={
            "login_url": "http://dvwa/login.php",
            "username": "admin",
            "password": "password",
            "token_field": "user_token",
            "extra_fields": {"Login": "Login"},
            "extra_cookies": {"security": "low"},
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["has_password"] is True
    assert "password" not in body               # لا تُعاد كلمة المرور
    assert body["username"] == "admin"

    got = client.get(f"/programs/{pid}/auth").json()
    assert got["configured"] is True
    assert got["token_field"] == "user_token"
    assert got["extra_cookies"] == {"security": "low"}
    assert "password" not in got


def test_get_profile_absent(client):
    pid = _program(client)
    assert client.get(f"/programs/{pid}/auth").json() == {"configured": False}


def test_update_keeps_password_when_blank(client, enc_key):
    pid = _program(client)
    client.put(f"/programs/{pid}/auth", json={"username": "admin", "password": "secret1"})
    # تحديث بلا كلمة مرور — يبقى المخزَّن.
    client.put(f"/programs/{pid}/auth", json={"username": "admin2"})
    assert client.get(f"/programs/{pid}/auth").json()["has_password"] is True


def test_load_login_config_decrypts(client, db_session, enc_key):
    pid = _program(client)
    client.put(
        f"/programs/{pid}/auth",
        json={"login_url": "http://x/login", "username": "admin", "password": "p@ss"},
    )
    cfg = load_login_config(db_session, pid)
    assert cfg["password"] == "p@ss"            # فُكّ التشفير
    assert cfg["url"] == "http://x/login"


def test_delete_profile(client, enc_key):
    pid = _program(client)
    client.put(f"/programs/{pid}/auth", json={"username": "admin", "password": "p"})
    assert client.delete(f"/programs/{pid}/auth").status_code == 204
    assert client.get(f"/programs/{pid}/auth").json() == {"configured": False}
    assert client.delete(f"/programs/{pid}/auth").status_code == 404


def test_authscan_derives_targets_from_url_scope(client):
    pid = _program(client)
    # أصل نطاق من نوع url — يصير هدف فحص مُصادَق دائم.
    client.post(
        f"/programs/{pid}/scope",
        json={"kind": "url", "identifier": "http://dvwa/vulnerabilities/xss_r/?name=x", "in_scope": True},
    )
    # بلا targets صريحة — تُشتقّ من النطاق؛ يمر الحارس ثم يحاول الجدولة (الطابور غير متاح => 503).
    r = client.post(f"/programs/{pid}/authscan", json={})
    assert r.status_code in (503, 200)          # تجاوز 422 => الأهداف اشتُقّت فعلاً


def test_authscan_no_targets_no_url_scope_422(client):
    pid = _program(client)
    assert client.post(f"/programs/{pid}/authscan", json={}).status_code == 422
