# vuln-automation-platform

منصة **self-hosted** لأتمتة recon وفحص الثغرات ضمن **نطاق مصرّح به فقط**
(برامج bug bounty على HackerOne التي وافقت على الاختبار، أو بيئات اختبار محلية
مثل OWASP Juice Shop / DVWA)، مع دمج محرك [Strix](https://github.com/usestrix/strix)
بالذكاء الاصطناعي.

> ⚠️ **تنبيه قانوني:** هذه الأداة تُشغّل أدوات فحص فعلية. لا تستخدمها أبدًا على أي
> هدف لا تملك إذنًا كتابيًا صريحًا باختباره. كل هدف يمر إجباريًا عبر
> **Scope Gatekeeper** ويُسجَّل في `audit_log`. انظر `AGENTS.md`.

## الحالة

**منفّذ: Phase 0 + Phase 1 + Phase 2.**

- **Phase 0** — هيكلية المستودع، `docker-compose` (Postgres + Redis + API)، `GET /health`.
- **Phase 1** — نماذج البيانات الستة (`programs`, `scope_assets`, `targets`,
  `scan_runs`, `findings`, `audit_log`) + migrations (Alembic) + CRUD للبرامج والنطاق.
- **Phase 2** — ⭐ **Scope Gatekeeper**: كل هدف يمر عبر فحص قبول/رفض ويُسجَّل في
  `audit_log`. out-of-scope يتغلّب دائمًا؛ ولا تطابق إطلاقًا = رفض.

المراحل اللاحقة (Recon، Scan، دمج Strix…) غير منفّذة بعد.

## نقاط الـ API الحالية

| Method | Path | الوصف |
|---|---|---|
| GET | `/health` | فحص صحة |
| POST | `/programs` | إنشاء برنامج |
| GET | `/programs` · `/programs/{id}` | قائمة / تفاصيل |
| POST | `/programs/{id}/scope` | إضافة asset للنطاق (in/out of scope) |
| GET | `/programs/{id}/scope` | قائمة النطاق |
| GET | `/programs/{id}/audit` | سجل تدقيق قرارات النطاق |
| POST | `/targets` | إضافة هدف — **يمر عبر Scope Gatekeeper** |
| GET | `/targets` | قائمة الأهداف |

### migrations

```bash
# توليد migration جديد بعد تعديل النماذج
python -m alembic revision --autogenerate -m "رسالة"
# تطبيق
python -m alembic upgrade head
```

## التشغيل السريع

```bash
cp .env.example .env          # عدّل القيم
docker compose -f docker/docker-compose.yml up --build
```

ثم تحقّق من الـ health check:

```bash
curl http://localhost:8000/health
# {"status":"ok","version":"0.0.0"}
```

## البنية

| المكوّن | الوصف |
|---|---|
| `api/` | تطبيق FastAPI (نقطة الدخول + الخدمات لاحقًا) |
| `workers/` | عمّال Celery لـ recon / scan / strix (لاحقًا) |
| `db/` | migrations قاعدة البيانات (Alembic لاحقًا) |
| `docker/` | `docker-compose.yml` و Dockerfiles |
| `reports/` | قوالب تقارير HackerOne (لاحقًا) |
| `tests/` | اختبارات |

## التطوير

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload
pytest
```
