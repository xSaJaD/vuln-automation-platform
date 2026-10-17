"""تشفير الحقول الحساسة (بيانات grey-box) باستخدام Fernet (AES-128 + HMAC).

المفتاح يُقرأ من البيئة (FIELD_ENCRYPTION_KEY) فقط. بدون مفتاح، التشفير مُعطّل
وأي محاولة تخزين سر تُرفض — لا نخزّن سرًّا بنص صريح أبدًا.
"""

from __future__ import annotations

from api.config import settings


class FieldCipher:
    def __init__(self, key: str | bytes):
        from cryptography.fernet import Fernet

        self._f = Fernet(key if isinstance(key, bytes) else key.encode())

    def encrypt(self, plaintext: str) -> str:
        return self._f.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self._f.decrypt(token.encode()).decode()


def generate_key() -> str:
    """يولّد مفتاح تشفير جديدًا (للتهيئة الأولى)."""
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


def get_cipher() -> FieldCipher | None:
    """يرجّع FieldCipher إن كان المفتاح مُهيّأً، وإلا None."""
    key = settings.field_encryption_key
    if not key:
        return None
    try:
        return FieldCipher(key)
    except Exception:
        return None
