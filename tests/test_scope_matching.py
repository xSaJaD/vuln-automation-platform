"""اختبارات محرّك المطابقة النقي — معيار قبول Phase 2.

يغطّي: نطاق مطابق، نطاق فرعي مطابق، نطاق مُستبعَد صراحة، نطاق غير موجود إطلاقًا.
"""

from api.services.scope_matching import ScopeRule, evaluate

SCOPE = [
    ScopeRule("domain", "example.com", in_scope=True),
    ScopeRule("wildcard", "*.example.com", in_scope=True),
    ScopeRule("wildcard", "secret.example.com", in_scope=False),  # مُستبعَد صراحة
    ScopeRule("cidr", "203.0.113.0/24", in_scope=True),
]


# ── معايير القبول الأربعة ──

def test_matching_domain_apex():
    """نطاق مطابق (apex) ضمن النطاق."""
    d = evaluate("example.com", SCOPE)
    assert d.allowed is True


def test_matching_subdomain():
    """نطاق فرعي يطابق wildcard ضمن النطاق."""
    d = evaluate("api.example.com", SCOPE)
    assert d.allowed is True


def test_explicitly_excluded_subdomain():
    """نطاق فرعي مُستبعَد صراحة => مرفوض رغم تطابقه مع wildcard المسموح."""
    d = evaluate("db.secret.example.com", SCOPE)
    assert d.allowed is False
    assert "مُستبعَد" in d.reason


def test_target_not_in_scope_at_all():
    """نطاق غير موجود إطلاقًا => مرفوض افتراضيًا."""
    d = evaluate("evil.com", SCOPE)
    assert d.allowed is False


# ── حالات إضافية مهمة ──

def test_wildcard_does_not_match_apex():
    """wildcard لا يطابق الـ apex — يحتاج قاعدة domain منفصلة."""
    only_wildcard = [ScopeRule("wildcard", "*.foo.com", in_scope=True)]
    assert evaluate("foo.com", only_wildcard).allowed is False
    assert evaluate("a.foo.com", only_wildcard).allowed is True


def test_ip_in_cidr():
    assert evaluate("203.0.113.50", SCOPE).allowed is True
    assert evaluate("203.0.114.1", SCOPE).allowed is False


def test_url_target_uses_host():
    assert evaluate("https://api.example.com/login?x=1", SCOPE).allowed is True


def test_out_of_scope_precedence_over_in_scope():
    """لو هدف يطابق in-scope و out-of-scope معًا، يفوز out-of-scope."""
    rules = [
        ScopeRule("wildcard", "*.example.com", in_scope=True),
        ScopeRule("domain", "admin.example.com", in_scope=False),
    ]
    assert evaluate("admin.example.com", rules).allowed is False


def test_empty_target_rejected():
    assert evaluate("", SCOPE).allowed is False


def test_repo_matching():
    rules = [ScopeRule("repo", "github.com/org/app", in_scope=True)]
    assert evaluate("https://github.com/org/app", rules).allowed is True
    assert evaluate("https://github.com/org/app.git", rules).allowed is True
    assert evaluate("github.com/org/other", rules).allowed is False
