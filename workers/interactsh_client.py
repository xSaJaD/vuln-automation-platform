"""عميل interactsh حقيقي — يلفّ أداة `interactsh-client` (subprocess) ويطبّق OobClient.

interactsh وكيل OOB معياري: يسجّل نطاقًا، وأي استعلام DNS/HTTP على نطاق فرعي منه
يُسجَّل. يشغّل كل فحص داخل الـ worker. **شغّل خادم interactsh خاص بك** (self-hosted)
ومرّره بـ -server لتجنّب المشاركة العامة.

ملاحظة: لا يُختبَر وحدويًا (subprocess)؛ المنطق الذي يستهلكه (oob_confirm) مختبَر ببديل.
"""

from __future__ import annotations

import json
import queue
import re
import secrets
import shutil
import subprocess
import threading

from workers.oob import Interaction

_DOMAIN_RE = re.compile(r"([a-z0-9]+\.[a-z0-9.-]*oast[a-z0-9.-]*)", re.I)


class InteractshClient:
    """يطبّق بروتوكول OobClient فوق أداة interactsh-client."""

    def __init__(self, server: str | None = None, token: str | None = None, timeout: int = 60):
        if shutil.which("interactsh-client") is None:
            raise RuntimeError("interactsh-client غير مثبّت في بيئة التشغيل (worker)")
        cmd = ["interactsh-client", "-json", "-silent"]
        if server:
            cmd += ["-server", server]
        if token:
            cmd += ["-token", token]
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        self._q: queue.Queue[Interaction] = queue.Queue()
        self._domain: str | None = None
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        # ننتظر ظهور النطاق المسجّل.
        import time
        deadline = time.time() + timeout
        while self._domain is None and time.time() < deadline:
            time.sleep(0.2)
        if self._domain is None:
            self.close()
            raise RuntimeError("تعذّر الحصول على نطاق interactsh")

    def _read(self) -> None:
        for line in self._proc.stdout or []:
            line = line.strip()
            if not line:
                continue
            if self._domain is None:
                m = _DOMAIN_RE.search(line)
                if m:
                    self._domain = m.group(1)
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and data.get("unique-id"):
                self._q.put(Interaction(
                    protocol=data.get("protocol", ""),
                    unique_id=data.get("unique-id", ""),
                    remote_address=data.get("remote-address", ""),
                ))

    def domain(self) -> str:
        return self._domain or ""

    def new_payload(self) -> tuple[str, str]:
        uid = secrets.token_hex(8)
        return uid, f"{uid}.{self._domain}"

    def poll(self) -> list[Interaction]:
        out: list[Interaction] = []
        while True:
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                break
        return out

    def close(self) -> None:
        try:
            self._proc.terminate()
        except Exception:
            pass
