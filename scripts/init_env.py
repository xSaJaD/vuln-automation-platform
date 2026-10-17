#!/usr/bin/env python3
"""يهيّئ ملف .env ويضيف FIELD_ENCRYPTION_KEY تلقائيًا.

- ينشئ .env من .env.example إن لم يكن موجودًا.
- يولّد مفتاح Fernet صالحًا (base64 لـ 32 بايت عشوائية) — بدون حاجة لـ cryptography.
- لا يكتب فوق مفتاح موجود إلا مع --force (الاستبدال يفقد فكّ تشفير الأسرار القديمة).

الاستخدام:
    python scripts/init_env.py
    python scripts/init_env.py --force
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"
EXAMPLE = ROOT / ".env.example"
VAR = "FIELD_ENCRYPTION_KEY"


def generate_key() -> str:
    # مفتاح Fernet = base64-urlsafe لـ 32 بايت عشوائية.
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def main() -> int:
    force = "--force" in sys.argv

    if not ENV.exists():
        if EXAMPLE.exists():
            ENV.write_text(EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
            print("✓ أُنشئ .env من .env.example")
        else:
            ENV.write_text("", encoding="utf-8")
            print("✓ أُنشئ .env فارغ")

    lines = ENV.read_text(encoding="utf-8").splitlines()
    key = generate_key()
    out: list[str] = []
    found = False

    for line in lines:
        if line.strip().startswith(VAR + "="):
            found = True
            current = line.split("=", 1)[1].strip()
            if current and not force:
                print(f"• {VAR} مضبوط مسبقًا — لم يتغيّر. استخدم --force للاستبدال.")
                return 0
            out.append(f"{VAR}={key}")
            print(f"✓ تم ضبط {VAR}" + (" (استبدال)" if current else ""))
        else:
            out.append(line)

    if not found:
        out.append(f"{VAR}={key}")
        print(f"✓ أُضيف {VAR}")

    ENV.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"  المفتاح: {key[:6]}…{key[-4:]}  (محفوظ في .env — لا ترفعه لـ git)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
