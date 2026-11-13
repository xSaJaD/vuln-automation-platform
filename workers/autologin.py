"""تسجيل دخول تلقائي بالاستدلال (بلا LLM).

يكتشف نموذج تسجيل الدخول في صفحة بنفسه — حقل المستخدم، حقل كلمة المرور، وأي
حقول مخفية (CSRF) أو أزرار submit — فيسجّل الدخول بلا أن يُدخل المستخدم أسماء
الحقول أو رابط النموذج يدويًا. يحتاج فقط اسم مستخدم وكلمة مرور (تُحفظ مرة واحدة).

HTTP يُحقَن (client فيه get/post/cookies) ليبقى المنطق قابلًا للاختبار بلا شبكة.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin

# أسماء شائعة لحقل المستخدم — ترجيح عند وجود أكثر من حقل نصّي.
_USER_HINTS = ("user", "email", "login", "name", "account", "uid")


class _FormParser(HTMLParser):
    """يستخرج كل النماذج ومدخلاتها من HTML."""

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "inputs": []}
        elif tag in ("input", "button") and self._cur is not None:
            self._cur["inputs"].append(
                {"type": (a.get("type") or "text").lower(), "name": a.get("name"), "value": a.get("value", "")}
            )

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def find_login_form(html: str) -> dict | None:
    """يلتقط أول نموذج يحوي حقل كلمة مرور، ويحدّد حقول المستخدم/المرور تلقائيًا.

    يرجّع {action, method, username_field, password_field, payload} أو None.
    payload يحوي الحقول المخفية وأزرار submit بقيمها كما هي (CSRF, Login=Login...).
    """
    parser = _FormParser()
    parser.feed(html or "")
    if parser._cur is not None:          # نموذج غير مُغلق — اعتبره مكتملًا
        parser.forms.append(parser._cur)

    for form in parser.forms:
        inputs = form["inputs"]
        pw = next((i for i in inputs if i["type"] == "password" and i["name"]), None)
        if not pw:
            continue
        # حقل المستخدم: نصّي/إيميل، يُرجّح الاسم المألوف، وإلا أول نصّي.
        text_inputs = [i for i in inputs if i["type"] in ("text", "email") and i["name"]]
        user = None
        for i in text_inputs:
            if any(h in (i["name"] or "").lower() for h in _USER_HINTS):
                user = i
                break
        if user is None and text_inputs:
            user = text_inputs[0]

        payload: dict[str, str] = {}
        for i in inputs:
            name = i["name"]
            if not name or i["type"] == "password":
                continue
            if user and name == user["name"]:
                continue
            # نمرّر المخفية وأزرار submit وبقية الحقول بقيمها (CSRF, Login=Login...).
            if i["type"] in ("hidden", "submit", "text", "email") or i["value"]:
                payload[name] = i["value"]

        return {
            "action": form["action"],
            "method": form["method"],
            "username_field": user["name"] if user else "username",
            "password_field": pw["name"],
            "payload": payload,
        }
    return None


def _find_login_link(html: str) -> str | None:
    """بحث بسيط عن رابط صفحة دخول (href يحوي login/signin)."""
    import re

    for m in re.finditer(r'href=["\']([^"\']+)["\']', html or "", re.IGNORECASE):
        href = m.group(1)
        if any(k in href.lower() for k in ("login", "signin", "sign-in", "auth")):
            return href
    return None


def auto_login(client, start_url: str, username: str, password: str) -> dict[str, str]:
    """يكتشف نموذج الدخول في start_url (أو يتبع رابط دخول) ويسجّل الدخول تلقائيًا.

    يرجّع قاموس الكوكيز بعد المحاولة (قد يكون بلا جلسة إن لم يُعثر على نموذج).
    """
    resp = client.get(start_url)
    html = resp.text
    base = getattr(resp, "url", None) or start_url

    form = find_login_form(html)
    if form is None:
        link = _find_login_link(html)
        if link:
            resp = client.get(urljoin(base, link))
            html = resp.text
            base = getattr(resp, "url", None) or base
            form = find_login_form(html)

    if form is not None and username is not None:
        data = dict(form["payload"])
        data[form["username_field"]] = username
        data[form["password_field"]] = password or ""
        action_url = urljoin(base, form["action"]) if form["action"] else base
        client.post(action_url, data)

    return dict(client.cookies())
