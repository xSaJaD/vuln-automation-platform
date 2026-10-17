"""اختبارات CRUD للبرامج + حراسة الأهداف عبر الـ API (Phase 1 + 2)."""


def test_program_crud_and_scope(client):
    # إنشاء برنامج
    r = client.post("/programs", json={"name": "Acme", "handle": "acme"})
    assert r.status_code == 201
    pid = r.json()["id"]

    # handle مكرر => 409
    assert client.post("/programs", json={"name": "x", "handle": "acme"}).status_code == 409

    # إضافة نطاق
    r = client.post(
        f"/programs/{pid}/scope",
        json={"kind": "wildcard", "identifier": "*.acme.com", "in_scope": True},
    )
    assert r.status_code == 201

    # نوع asset غير صالح => 422
    bad = client.post(f"/programs/{pid}/scope", json={"kind": "banana", "identifier": "x"})
    assert bad.status_code == 422

    # قائمة النطاق
    scope = client.get(f"/programs/{pid}/scope").json()
    assert len(scope) == 1


def test_target_approved_when_in_scope(client):
    pid = client.post("/programs", json={"name": "Acme", "handle": "acme"}).json()["id"]
    client.post(
        f"/programs/{pid}/scope",
        json={"kind": "wildcard", "identifier": "*.acme.com", "in_scope": True},
    )

    r = client.post("/targets", json={"program_id": pid, "value": "app.acme.com"})
    assert r.status_code == 201
    assert r.json()["status"] == "approved"


def test_target_rejected_when_out_of_scope(client):
    pid = client.post("/programs", json={"name": "Acme", "handle": "acme"}).json()["id"]
    client.post(
        f"/programs/{pid}/scope",
        json={"kind": "wildcard", "identifier": "*.acme.com", "in_scope": True},
    )

    r = client.post("/targets", json={"program_id": pid, "value": "notallowed.com"})
    assert r.status_code == 201
    assert r.json()["status"] == "rejected"

    # القرار مُسجَّل في سجل التدقيق
    audit = client.get(f"/programs/{pid}/audit").json()
    assert any(a["decision"] == "deny" for a in audit)
