"""اختبار نقطة متابعة المهام /tasks/{id} — تغذّي تحديث اللوحة الحيّ.

نحقن بديلًا وهميًا لـ celery_app.AsyncResult حتى لا نحتاج Redis/worker فعليًا.
"""

import workers.celery_app as celery_mod


class _FakeResult:
    def __init__(self, state, result=None):
        self.state = state
        self.result = result

    def ready(self):
        return self.state in ("SUCCESS", "FAILURE")

    def successful(self):
        return self.state == "SUCCESS"

    def failed(self):
        return self.state == "FAILURE"


def _patch(monkeypatch, fake):
    monkeypatch.setattr(celery_mod.celery_app, "AsyncResult", lambda _id: fake)


def test_task_pending(client, monkeypatch):
    _patch(monkeypatch, _FakeResult("PENDING"))
    r = client.get("/tasks/abc")
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "PENDING"
    assert body["ready"] is False
    assert "result" not in body


def test_task_success_returns_summary(client, monkeypatch):
    _patch(monkeypatch, _FakeResult("SUCCESS", {"status": "done", "correlated": 12}))
    body = client.get("/tasks/xyz").json()
    assert body["ready"] is True
    assert body["result"] == {"status": "done", "correlated": 12}


def test_task_failure_hides_traceback(client, monkeypatch):
    _patch(monkeypatch, _FakeResult("FAILURE", RuntimeError("secret internal detail")))
    body = client.get("/tasks/fail").json()
    assert body["ready"] is True
    assert "error" in body
    # لا يتسرّب نص الاستثناء الداخلي للمستخدم.
    assert "secret internal detail" not in str(body)


def test_task_backend_unreachable_is_safe(client, monkeypatch):
    def _boom(_id):
        raise ConnectionError("redis down")

    monkeypatch.setattr(celery_mod.celery_app, "AsyncResult", _boom)
    body = client.get("/tasks/whatever").json()
    assert body == {"task_id": "whatever", "state": "PENDING", "ready": False}
