# دليل التشغيل — فحص OWASP Juice Shop محليًا

دليل من الصفر: من `git clone` حتى أول تقرير، على **هدف تجريبي محلي مصرّح به**
(Juice Shop — تطبيق ويب هشّ عمدًا، تملكه وتشغّله أنت).

> ⚠️ هذا الدليل للأهداف المحلية التي تملكها فقط. لا تستخدم المنصّة على أي هدف
> لا تملك إذنًا صريحًا باختباره.

---

## 1. المتطلبات

- Docker + Docker Compose
- git
- (اختياري، لمحرك Strix) مفتاح LLM

تأكّد:
```bash
docker --version && docker compose version
```

---

## 2. التثبيت

```bash
git clone https://github.com/xSaJaD/vuln-automation-platform.git
cd vuln-automation-platform
python scripts/init_env.py        # ينشئ .env + مفتاح التشفير تلقائيًا
```

(اختياري — لتشغيل Strix بالذكاء الاصطناعي) عدّل `.env`:
```
STRIX_LLM=anthropic/claude-sonnet-4-6
LLM_API_KEY=مفتاحك
```

---

## 3. التشغيل (المنصّة + Juice Shop معًا)

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.demo.yml up --build -d
```

انتظر دقيقة، ثم تأكّد:
- **لوحة IQScan:** http://localhost:8000/
- **Juice Shop:** http://localhost:3000
- **صحة العمّال:** `curl http://localhost:8000/health/workers`

---

## ⭐ المسار الكامل من اللوحة (بلا تيرمنال)

افتح **http://localhost:8000/** وسوِّ كل شي من هناك:

1. اضغط **«+ برنامج»** بالأعلى → اكتب الاسم (مثلاً `Juice Shop Local`) → **إنشاء**.
2. في كرت **«النطاق المصرّح به»** أضف `juiceshop` (نوع: نطاق).
3. في شريط **«خط سير الفحص»** يتعبّأ حقل الهدف تلقائيًا بـ `juiceshop` — عدّله إلى
   **`juiceshop:3000`** (منفذ Juice Shop) ثم اضغط **«تشغيل الفحص»**.
4. تابع التقدّم حيًّا (recon → scan) — اللوحة تنتظر اكتمال المهمة فعليًا ثم تعرض
   النتائج تلقائيًا (قد ياخذ دقائق أول مرّة: nuclei ينزّل قوالبه).
5. في جدول **«النتائج»** اضغط أي صف لرؤية **اسم الثغرة** وتفاصيلها، ومنه:
   **«تأكيد الثغرة»** ثم **«مسودة تقرير»**.

> ما يصير فحص لهدف خارج النطاق — الحارس يرفض البذرة في الخادم قبل أي مهمة.

بقيّة الأقسام أدناه تشرح نفس الخطوات عبر الـ API (اختياري، للأتمتة).

---

## 4. إنشاء برنامج وإضافة النطاق

**من اللوحة (الأسهل):** افتح http://localhost:8000/ ، اضغط «+ برنامج» لإنشاء برنامج،
ثم في كرت "النطاق المصرّح به" أضف `juiceshop` (نوع: نطاق).

**أو عبر الـ API:**
```bash
# 1) أنشئ برنامجًا
curl -s -X POST localhost:8000/programs -H 'Content-Type: application/json' \
  -d '{"name":"Juice Shop Local","handle":"juiceshop-local"}'

# 2) أضف الهدف للنطاق (مضيف الحاوية على شبكة compose)
curl -s -X POST localhost:8000/programs/1/scope -H 'Content-Type: application/json' \
  -d '{"kind":"domain","identifier":"juiceshop","in_scope":true}'
```

تحقّق أن الحارس يقبل الهدف ويرفض ما سواه:
```bash
curl -s -X POST localhost:8000/targets -H 'Content-Type: application/json' \
  -d '{"program_id":1,"value":"http://juiceshop:3000"}'      # => approved
curl -s -X POST localhost:8000/targets -H 'Content-Type: application/json' \
  -d '{"program_id":1,"value":"http://example.com"}'          # => rejected
```

---

## 5. تشغيل الفحص

### الطريقة أ — Strix (موصى بها لـ Juice Shop · تحتاج LLM key)

Strix محرك اختبار بالذكاء الاصطناعي، مثالي لتطبيق ويب كامل:
```bash
curl -s -X POST localhost:8000/programs/1/strix -H 'Content-Type: application/json' \
  -d '{"target":"http://juiceshop:3000"}'
```
الهدف يمر عبر الحارس أولًا، ثم Strix يستكشف ويستغل، ويخزّن النتائج كـ findings.
تابع السجلّات: `docker compose -f docker/docker-compose.yml logs -f worker`

### الطريقة ب — nuclei (بدون LLM key)

```bash
curl -s -X POST localhost:8000/programs/1/pipeline -H 'Content-Type: application/json' \
  -d '{"seed":"juiceshop:3000"}'
```
يشغّل السلسلة: recon (يضيف الهدف ويتحقق أنه حيّ) → nuclei → دمج.

> ملاحظة المنفذ: Juice Shop على المنفذ غير القياسي 3000، لذا نمرّر `juiceshop:3000`.
> للأهداف الحقيقية بمنفذ قياسي (443) استخدم النطاق الجذر فقط.

---

## 6. عرض النتائج

**من اللوحة:** http://localhost:8000/ — راح تشوف المضيفات، مخطط الخطورة، وجدول النتائج.

**أو عبر الـ API:**
```bash
curl -s localhost:8000/programs/1/hosts        | python3 -m json.tool
curl -s localhost:8000/programs/1/findings     | python3 -m json.tool
# بعد الدمج:
curl -s -X POST localhost:8000/programs/1/correlate | python3 -m json.tool
curl -s localhost:8000/programs/1/correlated   | python3 -m json.tool
```

---

## 7. الفرز وتوليد التقرير

```bash
# أكّد نتيجة (مثلاً id=1) بعد مراجعتها
curl -s -X POST localhost:8000/correlated/1/triage \
  -H 'Content-Type: application/json' -d '{"status":"confirmed","actor":"sajo"}'

# ولّد مسودة تقرير Markdown (تُحفظ في reports/out/)
curl -s -X POST "localhost:8000/correlated/1/report?save=true" | python3 -m json.tool
```

> التقرير **مسودة** — راجِعه يدويًا قبل أي إرسال. لا إرسال آلي.

---

## 8. الإيقاف والتنظيف

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.demo.yml down
# لحذف البيانات أيضًا:
docker compose -f docker/docker-compose.yml -f docker/docker-compose.demo.yml down -v
```

---

## 9. استكشاف الأخطاء

| العَرَض | الحل |
|---|---|
| الـ worker ما يوصل Juice Shop | تأكّد أن الاثنين على نفس شبكة compose (استخدم ملفّي الـ compose معًا)؛ جرّب `docker compose exec worker ping -c1 juiceshop`. |
| النتيجة "clean" رغم توقّع ثغرات | لو ظهر WAF/حظر تُصنَّف `inconclusive`؛ لو فعلاً clean جرّب Strix (أعمق من nuclei). |
| Strix يفشل | تأكّد `LLM_API_KEY` مضبوط و`docker.sock` مركّب للـ worker. |
| 429 Too Many Requests | تجاوزت حد المعدّل؛ ارفع `RATE_LIMIT_PER_MINUTE` في `.env`. |
| لا تظهر نتائج | شغّل `/correlate` بعد الفحص، وراجع سجلّات الـ worker. |

---

**سير العمل الكامل:** نطاق → حارس → فحص (Strix/nuclei) → دمج → فرز → مسودة تقرير —
كله مع فرض نطاق صارم وتسجيل تدقيق، وبلا إرسال آلي.
