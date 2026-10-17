# vuln-automation-platform

منصة **self-hosted** لأتمتة recon وفحص الثغرات ضمن **نطاق مصرّح به فقط**
(برامج bug bounty على HackerOne التي وافقت على الاختبار، أو بيئات اختبار محلية
مثل OWASP Juice Shop / DVWA)، مع دمج محرك [Strix](https://github.com/usestrix/strix)
بالذكاء الاصطناعي.

> ⚠️ **تنبيه قانوني:** هذه الأداة تُشغّل أدوات فحص فعلية. لا تستخدمها أبدًا على أي
> هدف لا تملك إذنًا كتابيًا صريحًا باختباره. كل هدف يمر إجباريًا عبر
> **Scope Gatekeeper** ويُسجَّل في `audit_log`. انظر `AGENTS.md`.

## الحالة

**منفّذ: Phase 0 → Phase 12.**

- **Phase 0** — هيكلية المستودع، `docker-compose` (Postgres + Redis + API)، `GET /health`.
- **Phase 1** — نماذج البيانات (`programs`, `scope_assets`, `targets`, `hosts`,
  `scan_runs`, `findings`, `audit_log`) + migrations (Alembic) + CRUD.
- **Phase 2** — ⭐ **Scope Gatekeeper**: كل هدف يمر عبر فحص قبول/رفض ويُسجَّل في
  `audit_log`. out-of-scope يتغلّب دائمًا؛ ولا تطابق إطلاقًا = رفض.
- **Phase 3** — **Recon Workers** (Celery): subfinder → httpx → naabu. كل مضيف
  مكتشَف يمر عبر الحارس؛ **المضيفات خارج النطاق تُسجَّل لكن لا تُفحص إطلاقًا**.
- **Phase 4** — **Scan Workers** (nuclei): يفحص المضيفات الحيّة ضمن النطاق فقط،
  يُعيد التحقق من النطاق وقت الفحص، ويحوّل النتائج لـ `findings` (`source_tool='nuclei'`,
  `status=needs_review`). النتائج الخام تُحفظ في `strix_runs/`.
- **Phase 5** — **دمج Strix** (المحرك الرئيسي بالذكاء الاصطناعي): wrapper حول
  `strix` CLI، الهدف يمر عبر الحارس أولًا، النتائج تُنسَّق كـ `findings`
  (`source_tool='strix'`, `confirmed_by_strix=True`, `status=needs_review`).
- **Phase 6** — **Normalize + Correlate**: يدمج الـ findings حسب
  (host + endpoint + نوع الثغرة) في `correlated_findings` موحّدة؛ يجمع المصادر،
  يأخذ أعلى خطورة، ويعلّم `confirmed_by_strix` عند تطابق nuclei + Strix.
- **Phase 7** — **Triage + CVSS**: حاسبة CVSS v3.1 (تلقائي حسب النوع + تعديل يدوي)،
  وآلة حالات (`needs_review → confirmed → reported → resolved/duplicate/not_applicable`)،
  وكل تغيير يُسجَّل في `audit_log` (مين + متى).
- **Phase 8** — **توليد التقارير**: يملأ مسودة Markdown لكل finding **مؤكَّد**
  (وصف، CVSS، خطوات، أثر، إصلاح، PoC). **مسودة فقط — لا إرسال آلي لـ HackerOne.**
- **Phase 9** — **Orchestration**: سلسلة كاملة (`recon → scan → correlate`) بمهمة
  واحدة، **قفل تزامن** (Redis) يمنع تشغيلين متوازيين لنفس البرنامج، وجدولة دورية
  (Celery beat) — recon أسبوعي لكل برنامج نشط.
- **Phase 10** — **لوحة التحكم (IQScan)**: واجهة ويب احترافية بموشن جرافيك
  (خط أنابيب متحرّك، رادار recon، مخطط خطورة) يخدمها FastAPI على `/dashboard`،
  تتصل بالـ API مباشرة. افتح `http://localhost:8000/` بعد التشغيل.
- **Phase 11** — **الأمان وإدارة الأسرار**: تشفير الحقول الحسّاسة (Fernet)،
  تحديد المعدّل على الـ API، وفحص تسريب الأسرار (gitleaks) + checklist أمني.
  الأسرار من البيئة فقط. انظر `docs/SECURITY.md`.
- **Phase 12** — **الاختبار والنشر**: CI (GitHub Actions) يشغّل ruff + pytest +
  gitleaks على كل push/PR، اختبار تكامل end-to-end، و**أمر نشر واحد** (`make deploy`).
  انظر `docs/DEPLOY.md`.

المراحل اللاحقة (إشعارات، مرونة، HackerOne API، RBAC…) غير منفّذة بعد.

## نقاط الـ API الحالية

| Method | Path | الوصف |
|---|---|---|
| GET | `/` → `/dashboard` | **لوحة التحكم (Strix Console)** |
| GET | `/health` | فحص صحة |
| POST | `/programs` | إنشاء برنامج |
| GET | `/programs` · `/programs/{id}` | قائمة / تفاصيل |
| POST | `/programs/{id}/scope` | إضافة asset للنطاق (in/out of scope) |
| GET | `/programs/{id}/scope` | قائمة النطاق |
| GET | `/programs/{id}/audit` | سجل تدقيق قرارات النطاق |
| POST | `/targets` | إضافة هدف — **يمر عبر Scope Gatekeeper** |
| GET | `/targets` | قائمة الأهداف |
| POST | `/programs/{id}/recon` | تشغيل recon (البذرة تمر عبر الحارس أولًا) |
| GET | `/programs/{id}/hosts` | قائمة المضيفات المكتشَفة |
| POST | `/programs/{id}/scan` | تشغيل فحص nuclei على المضيفات الحيّة ضمن النطاق |
| POST | `/programs/{id}/strix` | تشغيل محرك Strix على هدف ضمن النطاق |
| GET | `/programs/{id}/findings` | قائمة النتائج الخام |
| POST | `/programs/{id}/correlate` | دمج النتائج في findings موحّدة |
| GET | `/programs/{id}/correlated` | قائمة الـ findings الموحّدة (مع CVSS) |
| POST | `/correlated/{id}/triage` | تغيير الحالة أو CVSS يدويًا (مُسجَّل) |
| POST | `/correlated/{id}/report` | توليد مسودة تقرير Markdown (للمؤكَّد فقط) |
| POST | `/programs/{id}/pipeline` | تشغيل السلسلة الكاملة (recon→scan→correlate) |
| POST | `/programs/{id}/credentials` | تخزين اعتماد grey-box **مُشفّرًا** |
| GET | `/programs/{id}/credentials` | قائمة الاعتمادات (بدون السر) |

> تشغيل الـ recon يتطلب حاوية `worker` شغّالة (`docker compose up`) — فيها
> subfinder/httpx/naabu. الاختبارات لا تحتاجها (تستخدم أدوات وهمية).

### migrations

```bash
# توليد migration جديد بعد تعديل النماذج
python -m alembic revision --autogenerate -m "رسالة"
# تطبيق
python -m alembic upgrade head
```

## التشغيل السريع

```bash
python scripts/init_env.py    # ينشئ .env ويضيف مفتاح التشفير تلقائيًا
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
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt   # محلي خفيف (بدون psycopg/celery)
uvicorn api.main:app --reload          # يستخدم SQLite تلقائيًا محليًا
pytest                                 # المتوقع: 20 passed
```

> `requirements.txt` الكامل (مع psycopg/celery) يُستخدم داخل حاويات Docker فقط.
