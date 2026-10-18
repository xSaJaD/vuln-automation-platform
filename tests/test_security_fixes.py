"""اختبارات إصلاحات المراجعة الأمنية: XSS، Path Traversal، Argument Injection."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from api.services.report_generator import _safe_segment, save_report
from workers.tools import safe_arg

# ── M1: Path Traversal في حفظ التقارير ──

def test_safe_segment_blocks_traversal():
    # الخاصية الأمنية: لا فاصل مسار ولا تسلّق للأعلى في الناتج.
    for malicious in ("../../etc/cron.d", "..", "/", "a/b/c", "..\\..\\x"):
        seg = _safe_segment(malicious)
        assert "/" not in seg and "\\" not in seg
        assert seg not in ("", ".", "..")
    assert _safe_segment("acme") == "acme"


def test_save_report_stays_within_out_dir(tmp_path):
    program = SimpleNamespace(handle="../../../../tmp/evil", name="x")
    finding = SimpleNamespace(id=7)
    path = save_report(str(tmp_path), program, finding, "# تقرير")
    # الملف داخل out_dir رغم handle الخبيث
    assert Path(path).resolve().is_relative_to(tmp_path.resolve())
    assert "evil" not in str(Path(path).parent.parent)  # لم يتسلّق للخارج


# ── M2: Argument Injection في أغلفة الأدوات ──

def test_safe_arg_rejects_leading_dash():
    with pytest.raises(ValueError):
        safe_arg("-oN/tmp/pwn")
    with pytest.raises(ValueError):
        safe_arg("--config=x")


def test_safe_arg_rejects_whitespace():
    with pytest.raises(ValueError):
        safe_arg("a.com b.com")
    with pytest.raises(ValueError):
        safe_arg("a.com\n-flag")


def test_safe_arg_accepts_valid():
    assert safe_arg(" app.example.com ") == "app.example.com"
    assert safe_arg("203.0.113.0/24") == "203.0.113.0/24"


def test_run_subfinder_rejects_injection():
    from workers.tools import run_naabu, run_subfinder

    # الرفض يحدث قبل محاولة تشغيل الأداة
    with pytest.raises(ValueError):
        run_subfinder("-d/evil")
    with pytest.raises(ValueError):
        run_naabu("-sV")


# ── H1: XSS في اللوحة (حارس انحدار على الملف المبني) ──

def test_dashboard_escapes_untrusted_fields():
    html = Path("api/static/index.html").read_text(encoding="utf-8")
    assert "function esc(" in html
    # الحقول غير الموثوقة تمر عبر esc() ولا تُحقن خامًا
    assert "esc(f.host)" in html
    assert "esc(f.vuln_type)" in html
    assert "esc(a.target_value)" in html
    assert "esc(s.identifier)" in html
    assert "'+f.host+'" not in html   # لا حقن خام
    assert "'+a.target_value+" not in html
