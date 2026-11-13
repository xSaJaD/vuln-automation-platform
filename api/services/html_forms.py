"""استخراج النماذج (forms) والروابط من HTML — بلا اعتماديات خارجية (stdlib فقط).

يُستخدم في اكتشاف نموذج التسجيل تلقائيًا، وفي التقاط الحقول المخفية (CSRF) قبل
إرسال التسجيل، وفي زحف روابط IDOR.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin


@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class Form:
    action: str = ""
    method: str = "get"
    fields: list[FormField] = field(default_factory=list)

    def field_names(self) -> list[str]:
        return [f.name for f in self.fields if f.name]

    def hidden(self) -> dict[str, str]:
        return {f.name: f.value for f in self.fields if f.type == "hidden" and f.name}


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[Form] = []
        self.links: list[str] = []
        self.scripts: list[str] = []      # روابط <script src>
        self._in_script = False
        self.inline_scripts: list[str] = []
        self._cur: Form | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = Form(action=a.get("action", ""), method=(a.get("method") or "get").lower())
            self.forms.append(self._cur)
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            self._cur.fields.append(
                FormField(name=a.get("name", ""), type=(a.get("type") or "text").lower(),
                          value=a.get("value", ""))
            )
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script = True

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline_scripts.append(data)

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None
        elif tag == "script":
            self._in_script = False


def parse(html: str, base_url: str = "") -> tuple[list[Form], list[str]]:
    """يرجّع (forms, absolute_links). الأخطاء في HTML تُتجاهَل بأمان."""
    pr = _parse(html, base_url)
    return pr.forms, pr.links


@dataclass
class ParsedPage:
    forms: list[Form]
    links: list[str]
    scripts: list[str]          # روابط ملفات JS خارجية (مطلقة)
    inline_scripts: list[str]   # أكواد JS المضمّنة


def parse_page(html: str, base_url: str = "") -> ParsedPage:
    """تحليل كامل: forms + links + <script src> + inline scripts."""
    return _parse(html, base_url)


def _parse(html: str, base_url: str) -> ParsedPage:
    p = _FormParser()
    try:
        p.feed(html or "")
    except Exception:
        pass
    for form in p.forms:
        if base_url and form.action:
            form.action = urljoin(base_url, form.action)
        elif not form.action:
            form.action = base_url
    links = [urljoin(base_url, h) for h in p.links] if base_url else list(p.links)
    scripts = [urljoin(base_url, s) for s in p.scripts] if base_url else list(p.scripts)
    return ParsedPage(forms=p.forms, links=links, scripts=scripts,
                      inline_scripts=list(p.inline_scripts))
