# vuln-automation-platform

منصة **self-hosted** لأتمتة recon وفحص الثغرات ضمن **نطاق مصرّح به فقط**
(برامج bug bounty على HackerOne التي وافقت على الاختبار، أو بيئات اختبار محلية
مثل OWASP Juice Shop / DVWA)، مع دمج محرك [Strix](https://github.com/usestrix/strix)
بالذكاء الاصطناعي.

> ⚠️ **تنبيه قانوني:** هذه الأداة تُشغّل أدوات فحص فعلية. لا تستخدمها أبدًا على أي
> هدف لا تملك إذنًا كتابيًا صريحًا باختباره. كل هدف يمر إجباريًا عبر
> **Scope Gatekeeper** ويُسجَّل في `audit_log`. انظر `AGENTS.md`.

## الحالة

**Phase 0 — الإعداد الأولي.** حاليًا المشروع يحتوي فقط على:

- هيكلية المستودع
- `docker-compose` أساسي (Postgres + Redis + API)
- API فارغ يرد `GET /health` فقط
- قاعدة الأسرار (`.env.example`) وقواعد السلوك العامة (`AGENTS.md`)

المراحل اللاحقة (Scope Gatekeeper، Recon، Scan، دمج Strix…) غير منفّذة بعد.

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
