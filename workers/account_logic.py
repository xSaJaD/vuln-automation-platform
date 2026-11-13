"""إنشاء حسابات اختبار تلقائيًا على الهدف — منطق نقي قابل للاختبار.

الغرض الوحيد: توفير حسابين مستقلين (A و B) لاختبار IDOR والثغرات التي تتطلب
جلسة مصادَقة. مُنفِّذ HTTP يُحقَن (register_fn) حتى يُستبدَل ببديل وهمي في الاختبار.

الحواجز (متوافقة مع AGENTS.md §0 — لا تجاوز ولا إساءة):
  • مضيف التسجيل يجب أن يمرّ عبر Scope Gatekeeper، وإلا لا يُنشأ شيء.
  • يجب أن يكون البرنامج قد فعّل allow_account_provisioning (إقرار ROE صريح).
  • حدّ أقصى صارم MAX_ACCOUNTS — هذا لاختبار IDOR (حسابان)، لا لإغراق الموقع.
  • مهلة بين الطلبات احترامًا لحدّ معدّل البرنامج (rate_limit_per_min).
  • الأسرار تُخزَّن مشفّرة فقط؛ كل إنشاء/رفض يُسجَّل في audit_log.
"""

from __future__ import annotations

import json
import secrets
import string
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from api.models.account import ProvisionedAccount
from api.models.audit import AuditLog
from api.models.program import Program
from api.services.crypto import get_cipher
from api.services.scope_gatekeeper import rules_for
from api.services.scope_matching import evaluate, host_of

MAX_ACCOUNTS = 3          # حسابان يكفيان لـ IDOR؛ الحدّ الصارم يمنع إغراق الموقع
DEFAULT_ACCOUNTS = 2


@dataclass(frozen=True)
class AccountRecipe:
    """وصف نموذج التسجيل في الموقع الهدف (يقدّمه الباحث لكل برنامج)."""

    register_url: str
    method: str = "POST"
    content_type: str = "form"                 # form | json
    fields: dict[str, str] = field(default_factory=dict)   # حقول ثابتة
    email_field: str = "email"
    password_field: str = "password"
    username_field: str | None = None
    success_status: tuple[int, ...] = (200, 201, 302)
    success_marker: str | None = None          # نص يجب وجوده في جسم الرد (اختياري)
    login_url: str | None = None               # لجلب جلسة بعد التسجيل (اختياري)
    login_fields: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RegisterRequest:
    url: str
    method: str
    content_type: str
    data: dict[str, str]


@dataclass
class RegisterResult:
    status_code: int
    body: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    token: str | None = None


@dataclass
class Identity:
    label: str
    email: str
    username: str
    password: str


# register_fn(RegisterRequest) -> RegisterResult   و   login مُعرَّف ضمن نفس الدالة
RegisterFn = Callable[[RegisterRequest], RegisterResult]


def _rand(n: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def make_identity(program: Program, label: str) -> Identity:
    """بريد plus-addressed على نطاق يملكه الباحث + كلمة مرور قوية عشوائية."""
    domain = (program.account_email_domain or "").strip().lstrip("@")
    if not domain:
        raise ValueError("account_email_domain غير مُعيَّن — لزوم صندوق بريد يملكه الباحث")
    tag = _rand(8, string.ascii_lowercase + string.digits)
    handle = program.handle.replace(".", "-")[:20]
    user = f"{handle}-{label}-{tag}"
    password = (
        _rand(4, string.ascii_uppercase) + _rand(4, string.ascii_lowercase)
        + _rand(4, string.digits) + _rand(4, "!@#$%^&*")
    )
    return Identity(label=label, email=f"{user}@{domain}", username=user, password=password)


def _build_request(recipe: AccountRecipe, ident: Identity) -> RegisterRequest:
    data = dict(recipe.fields)
    data[recipe.email_field] = ident.email
    data[recipe.password_field] = ident.password
    if recipe.username_field:
        data[recipe.username_field] = ident.username
    return RegisterRequest(recipe.register_url, recipe.method.upper(), recipe.content_type, data)


def _is_success(recipe: AccountRecipe, res: RegisterResult) -> bool:
    if res.status_code not in recipe.success_status:
        return False
    if recipe.success_marker and recipe.success_marker.lower() not in (res.body or "").lower():
        return False
    return True


def _audit(db, program_id, action, target, decision, reason, actor):
    db.add(AuditLog(action=action, target_value=str(target)[:500], program_id=program_id,
                    decision=decision, reason=reason, actor=actor))


def provision_accounts(
    db: Session,
    program: Program,
    recipe: AccountRecipe,
    register_fn: RegisterFn,
    *,
    count: int = DEFAULT_ACCOUNTS,
    actor: str = "provision",
    sleep: Callable[[float], None] = time.sleep,
) -> list[ProvisionedAccount]:
    """ينشئ حتى `count` حسابات (بحدّ MAX_ACCOUNTS) عبر نموذج تسجيل الموقع.

    يرفع PermissionError/ValueError قبل أي طلب شبكي إن اختلّ أي حاجز أمني.
    """
    if not program.allow_account_provisioning:
        _audit(db, program.id, "account_provision_block", recipe.register_url, "deny",
               "allow_account_provisioning مُعطَّل (لا إقرار ROE)", actor)
        db.commit()
        raise PermissionError("إنشاء الحسابات غير مُفعَّل لهذا البرنامج (ROE)")

    count = max(1, min(int(count), MAX_ACCOUNTS))

    # حارس النطاق: مضيف التسجيل (وتسجيل الدخول إن وُجد) يجب أن يكون ضمن النطاق.
    rules = rules_for(program)
    for url in filter(None, (recipe.register_url, recipe.login_url)):
        decision = evaluate(url, rules)
        _audit(db, program.id, "account_scope_check", url,
               "allow" if decision.allowed else "deny", decision.reason, actor)
        if not decision.allowed:
            db.commit()
            raise PermissionError(f"مضيف التسجيل خارج النطاق: {decision.reason}")

    cipher = get_cipher()
    if cipher is None:
        raise RuntimeError("التشفير غير مُهيّأ (FIELD_ENCRYPTION_KEY) — لا تُخزَّن أسرار بنص صريح")

    host = host_of(recipe.register_url)
    delay = 60.0 / program.rate_limit_per_min if program.rate_limit_per_min else 0.0

    created: list[ProvisionedAccount] = []
    for i in range(count):
        if i:
            sleep(delay)
        label = f"idor-{chr(ord('a') + i)}"
        ident = make_identity(program, label)
        acct = ProvisionedAccount(
            program_id=program.id, label=label, identifier=ident.email, register_host=host,
        )
        try:
            res = register_fn(_build_request(recipe, ident))
        except Exception as exc:  # فشل شبكي => يُسجَّل failed، لا يُدّعى نجاحًا
            acct.status = "failed"
            _audit(db, program.id, "account_provision", ident.email, "error", str(exc)[:300], actor)
            db.add(acct)
            created.append(acct)
            continue

        session = _session_payload(recipe, res, ident, register_fn)
        if _is_success(recipe, res) and session is not None:
            acct.status = "created"
            acct.secret_encrypted = cipher.encrypt(ident.password)
            acct.session_encrypted = cipher.encrypt(json.dumps(session))
            _audit(db, program.id, "account_provision", ident.email, "allow",
                   f"حساب اختبار مُنشأ ({label})", actor)
        else:
            acct.status = "failed"
            _audit(db, program.id, "account_provision", ident.email, "deny",
                   f"فشل التسجيل (HTTP {res.status_code})", actor)
        db.add(acct)
        created.append(acct)

    db.commit()
    return created


def _session_payload(recipe, res, ident, register_fn) -> dict | None:
    """جلسة الحساب بعد الإنشاء: من رد التسجيل، أو بتسجيل دخول صريح إن طُلب."""
    if recipe.login_url:
        data = dict(recipe.login_fields)
        data.setdefault(recipe.email_field, ident.email)
        data.setdefault(recipe.password_field, ident.password)
        try:
            login = register_fn(RegisterRequest(
                recipe.login_url, "POST", recipe.content_type, data))
        except Exception:
            return None
        if login.status_code not in recipe.success_status:
            return None
        return {"cookies": login.cookies, "token": login.token}
    if res.cookies or res.token:
        return {"cookies": res.cookies, "token": res.token}
    # لا جلسة = لا فائدة لاختبار IDOR.
    return None
