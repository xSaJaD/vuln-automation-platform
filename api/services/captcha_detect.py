"""كشف CAPTCHA / الحماية ضد الأتمتة — نقي وقابل للاختبار.

المشروع **لا يتخطّى** CAPTCHA (قاعدة AGENTS.md §0: لا evasion). عند كشفه يتوقف
إنشاء الحساب بنظافة ويُعلَّم captcha_blocked، ويُترك للباحث تجهيز الجلسة يدويًا.
"""

from __future__ import annotations

# علامات مزوّدي CAPTCHA/anti-bot الشائعة في صفحات التسجيل.
_PROVIDERS = {
    "recaptcha": ("g-recaptcha", "grecaptcha", "recaptcha/api.js", "recaptcha/enterprise"),
    "hcaptcha": ("h-captcha", "hcaptcha.com", "js.hcaptcha"),
    "turnstile": ("cf-turnstile", "challenges.cloudflare.com/turnstile"),
    "funcaptcha": ("funcaptcha", "arkoselabs"),
    "generic": ("captcha", "i am not a robot", "i'm not a robot", "are you human"),
}


def detect_captcha(html: str = "", headers: dict | None = None) -> str | None:
    """يرجّع اسم المزوّد إن وُجد CAPTCHA، وإلا None."""
    hay = (html or "").lower()
    for provider, markers in _PROVIDERS.items():
        if any(m in hay for m in markers):
            return provider
    return None
