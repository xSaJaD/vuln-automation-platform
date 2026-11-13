"""زحف خفيف لاكتشاف نماذج التسجيل/الدخول واستنتاج الـ recipe — منطق نقي.

لا شبكة هنا: يُحقَن fetcher(url) -> PageFetch. يحلّل HTML، يستخرج النماذج،
يصنّف كل نموذج (register / login / other) من حقوله وسياقه، ويبني AccountRecipe
جاهزة للإنشاء. يكتشف CAPTCHA فيوقف بدل الالتفاف عليه (سياسة المشروع).

الحدود: روابط ضمن نفس المضيف (الذي مرّ الحارس)، عمق محدود، عدد صفحات محدود.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin

from api.services.scope_matching import host_of
from workers.account_logic import AccountRecipe

MAX_PAGES = 40
MAX_DEPTH = 2

# مؤشّرات CAPTCHA في HTML (لا نلتف عليها — نوقف ونطلب جلسة يدوية).
CAPTCHA_MARKERS = (
    "g-recaptcha", "grecaptcha", "recaptcha", "h-captcha", "hcaptcha",
    "cf-turnstile", "turnstile", "funcaptcha", "arkoselabs", "data-sitekey",
    "captcha",
)

_REGISTER_HINTS = ("register", "signup", "sign-up", "sign_up", "join", "create-account",
                   "createaccount", "registration", "new-account")
_LOGIN_HINTS = ("login", "signin", "sign-in", "sign_in", "log-in", "authenticate", "session")

_EMAIL_HINTS = ("email", "e-mail", "mail", "username", "user", "login")
_PASSWORD_HINTS = ("password", "pass", "pwd", "passwd")
_CONFIRM_HINTS = ("confirm", "repeat", "retype", "verify", "again", "password2")
_USERNAME_HINTS = ("username", "user", "handle", "nickname", "display")


@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str = ""
    required: bool = False


@dataclass
class Form:
    action: str
    method: str = "POST"
    enctype: str = "application/x-www-form-urlencoded"
    fields: list[FormField] = field(default_factory=list)
    has_password: bool = False
    page_url: str = ""


@dataclass
class PageFetch:
    url: str
    status_code: int
    body: str = ""
    final_url: str | None = None   # بعد أي تحويل


@dataclass
class FormClassification:
    form: Form
    kind: str                      # register | login | other
    has_captcha: bool
    recipe: AccountRecipe | None   # للـ register فقط
    confidence: str                # high | medium | low


class _FormParser(HTMLParser):
    """يستخرج النماذج وحقولها + يرصد مؤشّرات CAPTCHA في الصفحة."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[Form] = []
        self.links: set[str] = set()
        self.captcha_in_page = False
        self._cur: Form | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        blob = " ".join(f"{k}={v}" for k, v in a.items()).lower()
        if any(m in blob for m in CAPTCHA_MARKERS):
            self.captcha_in_page = True

        if tag == "form":
            action = urljoin(self.base_url, a.get("action", "") or self.base_url)
            self._cur = Form(
                action=action,
                method=(a.get("method") or "POST").upper(),
                enctype=a.get("enctype") or "application/x-www-form-urlencoded",
                page_url=self.base_url,
            )
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            ftype = (a.get("type") or ("password" if tag == "input" else "text")).lower()
            name = a.get("name") or a.get("id") or ""
            if name and ftype not in ("submit", "button", "image", "reset"):
                self._cur.fields.append(FormField(
                    name=name, type=ftype, value=a.get("value", ""),
                    required="required" in a,
                ))
                if ftype == "password":
                    self._cur.has_password = True
        elif tag == "a":
            href = a.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                self.links.add(urljoin(self.base_url, href))

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _score(haystack: str, hints) -> int:
    return sum(1 for h in hints if h in haystack)


def _field_blob(f: FormField) -> str:
    return f"{f.name} {f.type}".lower()


def _pick(fields: list[FormField], hints, exclude=()) -> str | None:
    best, best_score = None, 0
    for f in fields:
        blob = _field_blob(f)
        if any(x in blob for x in exclude):
            continue
        s = _score(blob, hints)
        if s > best_score:
            best, best_score = f.name, s
    return best


def classify_form(form: Form, page_has_captcha: bool) -> FormClassification:
    """يصنّف النموذج ويبني recipe إن كان تسجيلًا."""
    ctx = f"{form.action} {form.page_url} {' '.join(_field_blob(f) for f in form.fields)}".lower()
    has_captcha = page_has_captcha or any(
        "captcha" in _field_blob(f) for f in form.fields
    )

    if not form.has_password:
        return FormClassification(form, "other", has_captcha, None, "low")

    reg_score = _score(ctx, _REGISTER_HINTS)
    login_score = _score(ctx, _LOGIN_HINTS)
    # وجود حقل تأكيد كلمة المرور إشارة قوية على التسجيل.
    pwd_fields = [f for f in form.fields if f.type == "password"]
    has_confirm = len(pwd_fields) >= 2 or any(
        _score(_field_blob(f), _CONFIRM_HINTS) for f in form.fields
    )
    if has_confirm:
        reg_score += 2

    if reg_score > login_score:
        kind = "register"
    elif login_score > 0:
        kind = "login"
    else:
        kind = "register" if has_confirm else "login"

    conf = "high" if abs(reg_score - login_score) >= 2 else "medium"

    recipe = None
    if kind == "register":
        recipe = _build_recipe(form, has_captcha)
        if recipe is None:
            kind, conf = "other", "low"
    return FormClassification(form, kind, has_captcha, recipe, conf)


def _build_recipe(form: Form, has_captcha: bool) -> AccountRecipe | None:
    email = _pick(form.fields, _EMAIL_HINTS, exclude=_PASSWORD_HINTS)
    password = _pick(
        [f for f in form.fields if f.type == "password"], _PASSWORD_HINTS + ("password",)
    ) or next((f.name for f in form.fields if f.type == "password"), None)
    if not email or not password:
        return None

    confirm = _pick([f for f in form.fields if f.type == "password" and f.name != password],
                    _CONFIRM_HINTS + _PASSWORD_HINTS)
    username = _pick(form.fields, _USERNAME_HINTS, exclude=_PASSWORD_HINTS + ("email", "mail"))
    if username in (email, password):
        username = None

    # حقول ثابتة: كل الحقول المخفية/الثابتة (CSRF tokens مثلًا) تُنقل كما هي.
    static: dict[str, str] = {}
    dynamic = {email, password, confirm, username}
    for f in form.fields:
        if f.name in dynamic:
            continue
        if f.type in ("hidden", "checkbox") or f.value:
            static[f.name] = f.value or ("on" if f.type == "checkbox" else "")

    content_type = "json" if "json" in form.enctype else "form"
    return AccountRecipe(
        register_url=form.action,
        method=form.method or "POST",
        content_type=content_type,
        fields=static,
        email_field=email,
        password_field=password,
        username_field=username,
        confirm_field=confirm,
    )


# fetcher(url) -> PageFetch
Fetcher = Callable[[str], PageFetch]


@dataclass
class CrawlResult:
    register: FormClassification | None = None
    login: FormClassification | None = None
    pages_visited: int = 0
    captcha_blocked: bool = False      # اكتُشف CAPTCHA على نموذج التسجيل
    forms: list[FormClassification] = field(default_factory=list)


def _same_host(url: str, root_host: str) -> bool:
    return host_of(url) == root_host


def _priority(url: str) -> int:
    u = url.lower()
    if any(h in u for h in _REGISTER_HINTS):
        return 0
    if any(h in u for h in _LOGIN_HINTS):
        return 1
    return 2


def discover_auth_forms(
    seed_url: str,
    fetcher: Fetcher,
    *,
    max_pages: int = MAX_PAGES,
    max_depth: int = MAX_DEPTH,
) -> CrawlResult:
    """يزحف ضمن نفس مضيف البذرة باحثًا عن أفضل نموذج تسجيل (وتسجيل دخول)."""
    root_host = host_of(seed_url)
    result = CrawlResult()
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(seed_url, 0)]

    while queue and result.pages_visited < max_pages:
        queue.sort(key=lambda it: (_priority(it[0]), it[1]))
        url, depth = queue.pop(0)
        norm = url.split("#", 1)[0]
        if norm in seen or not _same_host(norm, root_host):
            continue
        seen.add(norm)

        try:
            page = fetcher(norm)
        except Exception:
            continue
        result.pages_visited += 1
        if page.status_code >= 400 or not page.body:
            continue

        base = page.final_url or page.url
        parser = _FormParser(base)
        try:
            parser.feed(page.body)
        except Exception:
            continue

        for form in parser.forms:
            fc = classify_form(form, parser.captcha_in_page)
            result.forms.append(fc)
            if fc.kind == "register" and _better(result.register, fc):
                result.register = fc
            elif fc.kind == "login" and _better(result.login, fc):
                result.login = fc

        # وجدنا تسجيلًا عالي الثقة بلا CAPTCHA => نكتفي.
        if result.register and result.register.confidence == "high" \
                and not result.register.has_captcha:
            break

        if depth < max_depth:
            for link in parser.links:
                if link.split("#", 1)[0] not in seen and _same_host(link, root_host):
                    queue.append((link, depth + 1))

    if result.register and result.register.has_captcha:
        result.captcha_blocked = True
    return result


_CONF_RANK = {"high": 3, "medium": 2, "low": 1}


def _better(cur: FormClassification | None, new: FormClassification) -> bool:
    if cur is None:
        return True
    # نفضّل بلا CAPTCHA، ثم أعلى ثقة.
    if cur.has_captcha != new.has_captcha:
        return new.has_captcha is False
    return _CONF_RANK[new.confidence] > _CONF_RANK[cur.confidence]
