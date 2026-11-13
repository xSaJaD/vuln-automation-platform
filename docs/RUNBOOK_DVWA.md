# دليل التشغيل — فحص DVWA محليًا

دليل من الصفر: من `git clone` حتى أول تقرير، على **هدف تجريبي محلي مصرّح به**
(DVWA — Damn Vulnerable Web Application، تطبيق ويب هشّ عمدًا، تملكه وتشغّله أنت).

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

## 3. التشغيل (المنصّة + DVWA معًا)

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.demo.yml up --build -d
```

انتظر دقيقة، ثم:
- **لوحة IQScan:** http://localhost:8000/
- **DVWA:** http://localhost:8080  — سجّل الدخول `admin` / `password`، واضغط
  **«Create / Reset Database»** مرّة واحدة لتهيئة DVWA.
- **صحة العمّال:** `curl http://localhost:8000/health/workers`

---

## ⭐ المسار الكامل من اللوحة (بلا تيرمنال)

افتح **http://localhost:8000/** وسوِّ كل شي من هناك:

1. (أعلى اليمين) زر **اللغة** يبدّل بين العربي والإنكليزي في أي وقت.
2. اضغط **«+ برنامج»** → اكتب الاسم (مثلاً `DVWA Local`) → **إنشاء**.
3. في كرت **«النطاق المصرّح به»** أضف `dvwa` (نوع: نطاق). تقدر تحذف أي نطاق
   بزر **×** جنبه.
4. في شريط **«خط سير الفحص»**:
   - حقل الهدف يتعبّأ تلقائيًا بـ `dvwa`.
   - **مفتاح «فحص بـ Strix»**: فعّله لتشغيل محرك الذكاء الاصطناعي ضمن السلسلة
     (يحتاج `LLM_API_KEY`). إذا تركته مطفأ، الفحص بـ nuclei فقط **والموشن جرافيك
     لا يمرّ على مرحلة Strix**.
   - اضغط **«تشغيل الفحص»**.
5. تابع التقدّم حيًّا — اللوحة تنتظر اكتمال المهمة فعليًا ثم تعرض النتائج تلقائيًا
   (أول تشغيل ياخذ دقائق: nuclei ينزّل قوالبه).
6. في جدول **«النتائج»** اضغط أي صف لرؤية **اسم الثغرة** وتفاصيلها، ومنه:
   **«تأكيد الثغرة»** → **«مسودة تقرير»**، أو **«حذف النتيجة»** (مثلاً false-positive).

> ما يصير فحص لهدف خارج النطاق — الحارس يرفض البذرة في الخادم قبل أي مهمة.

بقيّة الأقسام أدناه تشرح نفس الخطوات عبر الـ API (اختياري، للأتمتة).

---

## 4. إنشاء برنامج وإضافة النطاق (عبر الـ API)

```bash
# 1) أنشئ برنامجًا
curl -s -X POST localhost:8000/programs -H 'Content-Type: application/json' \
  -d '{"name":"DVWA Local","handle":"dvwa-local"}'

# 2) أضف الهدف للنطاق (مضيف الحاوية على شبكة compose)
curl -s -X POST localhost:8000/programs/1/scope -H 'Content-Type: application/json' \
  -d '{"kind":"domain","identifier":"dvwa","in_scope":true}'
```

تحقّق أن الحارس يقبل الهدف ويرفض ما سواه:
```bash
curl -s -X POST localhost:8000/targets -H 'Content-Type: application/json' \
  -d '{"program_id":1,"value":"http://dvwa"}'        # => approved
curl -s -X POST localhost:8000/targets -H 'Content-Type: application/json' \
  -d '{"program_id":1,"value":"http://example.com"}'  # => rejected
```

---

## 5. تشغيل الفحص (عبر الـ API)

### الطريقة أ — nuclei (بدون LLM key)

```bash
curl -s -X POST localhost:8000/programs/1/pipeline -H 'Content-Type: application/json' \
  -d '{"seed":"dvwa"}'
```

### الطريقة ب — فحص مُصادَق دائم (DAST) بلا Strix ⭐

النظام **يسجّل دخولًا دائمًا** بإعداد يُحفظ مرة واحدة (كلمة المرور مشفّرة Fernet)،
ويشغّل nuclei بوضع fuzzing على البارامترات لاكتشاف XSS/SQLi — بلا أي LLM.

**الإعداد لمرة واحدة (من اللوحة):**
1. اضغط **«⚙ إعداد الدخول»** → عبّئ: الرابط `http://dvwa/login.php`، المستخدم `admin`،
   كلمة المرور `password`، حقل التوكن `user_token`، حقول إضافية `Login=Login`،
   كوكيز إضافية `security=low` → **حفظ**. (يُخزَّن مشفّرًا ويُعاد استخدامه كل مرة.)
2. أضف أهداف الفحص للنطاق بنوع **url** (مثلاً `http://dvwa/vulnerabilities/xss_r/?name=test`).
3. اضغط **«فحص مُصادَق»** — يسجّل الدخول بالإعداد المحفوظ ويفحص أهداف الـ url. خلاص.

**أو عبر الـ API:**
```bash
# 1) احفظ ملف المصادقة مرة واحدة (كلمة المرور تُخزَّن مشفّرة)
curl -s -X PUT localhost:8000/programs/1/auth -H 'Content-Type: application/json' -d '{
  "login_url":"http://dvwa/login.php","username":"admin","password":"password",
  "token_field":"user_token","extra_fields":{"Login":"Login"},"extra_cookies":{"security":"low"}}'

# 2) أضف أهداف url للنطاق
curl -s -X POST localhost:8000/programs/1/scope -H 'Content-Type: application/json' -d '{
  "kind":"url","identifier":"http://dvwa/vulnerabilities/xss_r/?name=test","in_scope":true}'

# 3) شغّل الفحص المُصادَق (يستخدم المحفوظ تلقائيًا — بلا تمرير كلمة مرور)
curl -s -X POST localhost:8000/programs/1/authscan -H 'Content-Type: application/json' -d '{}'
```

> ⚠️ لازم تسوّي **Create/Reset Database** و**DVWA Security = Low** أولًا (القسم 3).
> يتطلب `FIELD_ENCRYPTION_KEY` بالـ `.env` (ينشئه `scripts/init_env.py` تلقائيًا) لتخزين كلمة المرور.

### الطريقة ج — فحص ذاتي (دخول + زحف تلقائي) بلا LLM ⭐⭐

النظام يسجّل دخولًا بنفسه (يكتشف نموذج الدخول تلقائيًا)، يزحف (katana) لاكتشاف كل
الصفحات والبارامترات، ثم يفحصها — بإدخال **رابط بداية واحد فقط**.

**التحضير لمرة واحدة:** احفظ بيانات الدخول عبر **«⚙ إعداد الدخول»** (أو PUT /auth) —
تكفي `username`+`password` (رابط النموذج وحقوله تُكتشف تلقائيًا).

**من اللوحة:** حقل الهدف = `http://dvwa/` → اضغط **«فحص ذاتي»**. خلاص.

**أو عبر الـ API:**
```bash
curl -s -X POST localhost:8000/programs/1/autoscan -H 'Content-Type: application/json' \
  -d '{"seed":"http://dvwa/"}'
```

> لا تحتاج تحديد أهداف url يدويًا هنا — الزاحف يكتشفها. يعمل على أي موقع تملكه.

### الطريقة د — فحص عميق عبر OWASP ZAP (بلا LLM) ⭐⭐⭐

أعمق فحص بلا ذكاء اصطناعي: ZAP يزحف ويشغّل **Active Scan مُصادَق** (نمرّر له كوكي
الجلسة من تسجيل الدخول التلقائي)، فيكتشف ثغرات **POST/الحالة** اللي ما يلگاها nuclei:
Command Injection، SQLi (POST)، File Upload، CSRF…

**التشغيل** (ZAP ثقيل، لذا ملف compose إضافي):
```bash
docker compose -f docker/docker-compose.yml \
  -f docker/docker-compose.demo.yml \
  -f docker/docker-compose.zap.yml up -d --build
```

**الاستخدام:** احفظ إعداد الدخول مرة (⚙)، وبعدها حقل الهدف = `http://dvwa/` →
اضغط **«فحص عميق (ZAP)»**. يسجّل دخول → يزحف → active scan → تظهر الثغرات.

**أو عبر الـ API:**
```bash
curl -s -X POST localhost:8000/programs/1/zapscan -H 'Content-Type: application/json' \
  -d '{"seed":"http://dvwa/"}'
```

> ZAP ياخذ وقتًا أطول (دقائق). لو طلعت رسالة «ZAP غير متاح» تأكّد إنك شغّلت ملف
> `docker-compose.zap.yml`. غيّر `ZAP_API_KEY` في `.env` لمفتاح قوي خارج التجربة المحلية.

### الطريقة هـ — مع Strix (تحتاج LLM key)

```bash
curl -s -X POST localhost:8000/programs/1/pipeline -H 'Content-Type: application/json' \
  -d '{"seed":"dvwa","use_strix":true}'
```
السلسلة: recon → nuclei → (Strix اختياري) → دمج.

> ملاحظة المنفذ: DVWA داخل الشبكة على `dvwa:80` (منفذ قياسي)، لذا البذرة `dvwa`
> تكفي. على المضيف هو متاح على `http://localhost:8080`.

تابع المهمة:
```bash
# task_id يرجع من الأمر أعلاه
curl -s localhost:8000/tasks/<task_id> | python3 -m json.tool
```

---

## 6. عرض النتائج

**من اللوحة:** http://localhost:8000/ — المضيفات، مخطط الخطورة، وجدول النتائج.

**أو عبر الـ API:**
```bash
curl -s localhost:8000/programs/1/hosts        | python3 -m json.tool
curl -s localhost:8000/programs/1/correlated   | python3 -m json.tool
```

---

## 7. الفرز وتوليد التقرير وحذف نتيجة

```bash
# أكّد نتيجة (مثلاً id=1) بعد مراجعتها
curl -s -X POST localhost:8000/correlated/1/triage \
  -H 'Content-Type: application/json' -d '{"status":"confirmed","actor":"sajo"}'

# ولّد مسودة تقرير Markdown (تُحفظ في reports/out/)
curl -s -X POST "localhost:8000/correlated/1/report?save=true" | python3 -m json.tool

# احذف نتيجة (false-positive مثلاً)
curl -s -X DELETE localhost:8000/correlated/1
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
| الـ worker ما يوصل DVWA | تأكّد أن الاثنين على نفس شبكة compose (استخدم ملفّي الـ compose معًا)؛ جرّب `docker compose exec worker ping -c1 dvwa`. |
| DVWA يرجّع redirect للـ setup | افتح http://localhost:8080 وسجّل الدخول واضغط Create/Reset Database مرّة. |
| النتيجة "clean" رغم توقّع ثغرات | لو ظهر WAF/حظر تُصنَّف `inconclusive`؛ لو فعلاً clean فعّل Strix (أعمق من nuclei). |
| Strix يفشل | تأكّد `LLM_API_KEY` مضبوط و`docker.sock` مركّب للـ worker. |
| 429 Too Many Requests | تجاوزت حد المعدّل؛ ارفع `RATE_LIMIT_PER_MINUTE` في `.env`. |
| لا تظهر نتائج | راجع سجلّات الـ worker؛ السلسلة تدمج تلقائيًا في نهايتها. |

---

**سير العمل الكامل:** نطاق → حارس → فحص (nuclei/Strix) → دمج → فرز → مسودة تقرير —
كله من اللوحة، مع فرض نطاق صارم وتسجيل تدقيق، وبلا إرسال آلي.
