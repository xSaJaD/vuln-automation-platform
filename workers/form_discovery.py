"""اكتشاف نموذج التسجيل تلقائيًا بالزحف — نقي وقابل للاختبار.

يزحف عددًا صغيرًا من المسارات المرشّحة ضمن النطاق، يحلّل الـ forms، ويختار النموذج
الذي يشبه التسجيل (فيه كلمة مرور + بريد/اسم مستخدم). يبني AccountRecipe مقترحًا.

جالب الصفحات (fetch) محقون حتى يُختبَر بلا شبكة. الزحف محدود (max_pages) ولا يخرج
عن مضيف البذرة — ليس زاحفًا واسعًا.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin

from api.services.captcha_detect import detect_captcha
from api.services.html_forms import Form, parse
from api.services.scope_matching import host_of
from workers.account_logic import AccountRecipe

# المسارات الشائعة لصفحات التسجيل (تُجرَّب أولًا قبل اتباع الروابط).
CANDIDATE_PATHS = (
    "/register", "/signup", "/sign-up", "/users/new", "/account/register",
    "/auth/register", "/accounts/signup", "/join", "/create-account", "/registration",
)
MAX_PAGES = 12

_EMAIL_HINTS = ("email", "e-mail", "mail", "login")
_USER_HINTS = ("user", "username", "handle", "name", "nickname")
_PASS_HINTS = ("password", "passwd", "pwd", "pass")
_CONFIRM_HINTS = ("confirm", "repeat", "retype", "verification", "again", "_2")


@dataclass
class FetchResult:
    status_code: int
    html: str = ""
    final_url: str = ""


# fetch(url) -> FetchResult
FetchFn = Callable[[str], FetchResult]


@dataclass
class Discovery:
    recipe: AccountRecipe | None
    captcha: str | None
    page_url: str | None
    reason: str


def _field_like(names: list[str], hints: tuple[str, ...], *, avoid=()) -> str | None:
    for n in names:
        low = n.lower()
        if any(a in low for a in avoid):
            continue
        if any(h in low for h in hints):
            return n
    return None


def _looks_like_registration(form: Form) -> bool:
    names = [n.lower() for n in form.field_names()]
    has_pw = any(any(h in n for h in _PASS_HINTS) for n in names)
    has_id = any(any(h in n for h in _EMAIL_HINTS + _USER_HINTS) for n in names)
    return has_pw and has_id


def _recipe_from_form(form: Form, page_url: str) -> AccountRecipe | None:
    names = form.field_names()
    # كلمة المرور: أول حقل password ليس "تأكيد".
    pw = _field_like(names, _PASS_HINTS, avoid=_CONFIRM_HINTS) or _field_like(names, _PASS_HINTS)
    email = _field_like(names, _EMAIL_HINTS)
    user = _field_like(names, _USER_HINTS, avoid=("email",))
    if not pw or not (email or user):
        return None

    # حقول ثابتة: المخفية (CSRF) + حقل تأكيد كلمة المرور (نملؤه بنفس القيمة لاحقًا).
    fields = dict(form.hidden())
    action = urljoin(page_url, form.action) if form.action else page_url
    return AccountRecipe(
        register_url=action,
        method=(form.method or "post").upper() if form.method != "get" else "POST",
        content_type="form",
        fields=fields,
        email_field=email or user,
        password_field=pw,
        username_field=user if (user and user != (email or user)) else None,
        form_page_url=page_url,            # لإعادة جلب حقول CSRF الطازجة وقت الإنشاء
        confirm_password_field=_field_like(names, _CONFIRM_HINTS),
        success_status=(200, 201, 302),
    )


def discover_registration(
    seed: str, fetch: FetchFn, *, max_pages: int = MAX_PAGES
) -> Discovery:
    """يزحف من البذرة بحثًا عن نموذج تسجيل. البذرة يُفترض أنها مرّت الحارس مسبقًا."""
    base = seed if "://" in seed else f"https://{seed}"
    seed_host = host_of(base)

    queue = [urljoin(base, p) for p in CANDIDATE_PATHS] + [base]
    seen: set[str] = set()
    captcha_seen: str | None = None

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen or host_of(url) != seed_host:   # لا يخرج عن مضيف البذرة
            continue
        seen.add(url)
        try:
            res = fetch(url)
        except Exception:
            continue
        if res.status_code != 200 or not res.html:
            continue

        page_url = res.final_url or url
        forms, links = parse(res.html, page_url)
        for form in forms:
            if _looks_like_registration(form):
                captcha = detect_captcha(res.html)
                recipe = _recipe_from_form(form, page_url)
                if recipe:
                    return Discovery(recipe=recipe, captcha=captcha, page_url=page_url,
                                     reason=f"نموذج تسجيل على {page_url}"
                                            + (f" (CAPTCHA: {captcha})" if captcha else ""))
                captcha_seen = captcha_seen or captcha

        # اتبع روابط التسجيل المحتملة فقط (توسّع محدود).
        for link in links:
            if host_of(link) == seed_host and any(
                k in link.lower() for k in ("regist", "signup", "sign-up", "join", "account")
            ):
                if link not in seen:
                    queue.append(link)

    return Discovery(recipe=None, captcha=captcha_seen, page_url=None,
                     reason="لم يُعثر على نموذج تسجيل ضمن المسارات المزحوفة")
