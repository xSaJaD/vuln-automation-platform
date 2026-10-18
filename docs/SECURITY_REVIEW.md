# المراجعة الأمنية — IQScan

مراجعة شاملة للكود المصدري. التاريخ: 2026-10-18.

## الملخّص

راجعنا المنصّة بحثًا عن ثغرات في: فرض النطاق، الحقن (SQL/Command/Argument/XSS)،
Path Traversal، المصادقة والصلاحيات، إدارة الأسرار، SSRF، وDoS.

**النتيجة:** 3 ثغرات حقيقية (عولجت) + تحسينات. الأساسيات سليمة.

---

## الثغرات المُعالَجة ✅

### H1 — Stored XSS في لوحة التحكم (عالية) — مُصلَحة
- **المكان:** `api/static/index.html`
- **المشكلة:** عرض بيانات الفحص (`host`, `vuln_type`, `target_value`, `identifier`…)
  عبر `innerHTML` بدون تهريب. مهاجم يتحكّم بنطاق فرعي أو استجابة هدف يحقن JavaScript
  ينفَّذ بمتصفح المحلّل بنفس أصل الـ API.
- **الإصلاح:** دالة `esc()` تهرّب HTML، مطبّقة على كل الحقول غير الموثوقة.

### M1 — Path Traversal في حفظ التقارير (متوسطة) — مُصلَحة
- **المكان:** `api/services/report_generator.py` → `save_report`
- **المشكلة:** `os.path.join(out_dir, program.handle)` مع handle غير مُطهَّر يسمح
  بكتابة ملفات خارج `reports/out/`.
- **الإصلاح:** `_safe_segment()` يطهّر الاسم + فحص `commonpath` يضمن بقاء المسار داخل
  المجلد.

### M2 — Argument Injection في أغلفة الأدوات (متوسطة) — مُصلَحة
- **المكان:** `workers/tools.py`, `workers/strix_cli.py`
- **المشكلة:** تمرير مضيف/هدف يبدأ بـ `-` كوسيط لـ subfinder/naabu/strix قد يُفسَّر
  كـ flag (مثل `-oN/tmp/x`).
- **الإصلاح:** `safe_arg()` يرفض ما يبدأ بـ `-` أو يحوي مسافات/محارف تحكّم.

> كل الإصلاحات مغطّاة باختبارات في `tests/test_security_fixes.py`.

---

## تحسينات موصى بها (منخفضة الخطورة)

| # | المكان | التوصية |
|---|---|---|
| L1 | `services/ratelimit.py` | تنظيف دوري للقاموس (تسريب ذاكرة)، ومراعاة reverse proxy. |
| L2 | `services/auth.py` | قيد فريد/قفل على bootstrap لتفادي سباق إنشاء أول مفتاح. |
| L3 | `models/audit.py` | سياسة retention لـ `audit_log` (امتلاء القرص). |
| L4 | `docker-compose.yml` | `docker.sock` = صلاحية root على المضيف؛ شغّل الـ worker single-tenant أو rootless. |

---

## نقاط القوة المؤكَّدة

- **لا SQL Injection** — SQLAlchemy ORM بمعاملات حصريًا.
- **لا Command Injection** — `subprocess` بقوائم، بلا `shell=True`.
- **الأسرار** مُشفّرة (Fernet) ومن البيئة فقط؛ لا تُعاد عبر الـ API.
- **Scope Gatekeeper** — out-of-scope يتغلّب، wildcard دقيق، الافتراضي رفض، إعادة
  تحقق وقت الفحص، وتعطيل الأصول الخارجة من النطاق.
- **لا إرسال آلي** — موافقة بشرية صريحة ثلاثية الطبقات قبل أي إرسال لـ HackerOne.
- كل القرارات تُسجَّل في `audit_log`.
