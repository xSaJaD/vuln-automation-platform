"""اختبار تكامل end-to-end — معيار قبول Phase 12.

يمرّ على السلسلة كاملة عبر الـ API والمنطق معًا:
برنامج → نطاق → pipeline (recon+scan+correlate) → triage → مسودة تقرير.
يستخدم أدوات وهمية (بدون شبكة) لكن يمرّ بكل الطبقات الحقيقية.
"""

from api.models.program import Program
from workers.orchestration import run_pipeline
from workers.recon_logic import ReconTools
from workers.scan_logic import ScanTools


def _recon_tools():
    return ReconTools(
        subfinder=lambda d: ["app.example.com"],
        httpx=lambda hosts: [
            {"input": h, "status_code": 200, "title": "App", "tech": ["nginx"]} for h in hosts
        ],
        naabu=lambda h: [443],
    )


def _scan_tools():
    return ScanTools(
        nuclei=lambda targets: [
            {
                "template-id": "sqli",
                "info": {"name": "SQL Injection", "severity": "high"},
                "host": t,
                "matched-at": f"https://{t}/search",
            }
            for t in targets
        ]
    )


def test_full_flow(client, db_session):
    # 1) إنشاء برنامج
    pid = client.post("/programs", json={"name": "Acme", "handle": "acme"}).json()["id"]

    # 2) إضافة نطاق مصرّح به
    r = client.post(
        f"/programs/{pid}/scope",
        json={"kind": "wildcard", "identifier": "*.example.com", "in_scope": True},
    )
    assert r.status_code == 201

    # 3) تشغيل السلسلة (نفس منطق مهمة pipeline.run_full، بأدوات وهمية)
    program = db_session.get(Program, pid)
    correlated = run_pipeline(db_session, program, "example.com", _recon_tools(), _scan_tools())
    assert correlated, "السلسلة لم تُنتج أي finding موحّد"

    # 4) الـ API يرى المضيفات والنتائج الموحّدة
    hosts = client.get(f"/programs/{pid}/hosts").json()
    assert any(h["hostname"] == "app.example.com" and h["in_scope"] for h in hosts)

    corr = client.get(f"/programs/{pid}/correlated").json()
    assert corr and corr[0]["cvss_score"] is not None  # CVSS محسوب تلقائيًا
    cf_id = corr[0]["id"]

    # 5) triage → confirmed
    t = client.post(f"/correlated/{cf_id}/triage", json={"status": "confirmed", "actor": "sajo"})
    assert t.status_code == 200 and t.json()["status"] == "confirmed"

    # 6) توليد مسودة التقرير
    rep = client.post(f"/correlated/{cf_id}/report", params={"save": "false"})
    assert rep.status_code == 200
    body = rep.json()
    assert body["draft"] is True
    assert "لا تُرسَل آليًا إلى HackerOne" in body["markdown"]  # قاعدة عدم الإرسال الآلي
