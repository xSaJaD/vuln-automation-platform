# الأمان — قائمة المراجعة (Phase 11)

منصّة IQScan تُشغّل أدوات فحص فعلية وتتعامل مع مفاتيح حسّاسة. القائمة التالية
تُراجَع قبل أي نشر.

## 1. الأسرار

- [ ] **كل الأسرار من البيئة فقط** (`.env` / Docker secrets) — لا أسرار في الكود.
- [ ] `.env` مُستبعَد في `.gitignore` (موجود). يُرفع `.env.example` فقط بقيم نائبة.
- [ ] `FIELD_ENCRYPTION_KEY` مُعيّن في الإنتاج. ولّده بـ:
  ```bash
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  ```
- [ ] مفاتيح LLM و HackerOne لا تظهر في السجلّات ولا الاستجابات.

## 2. الحقول الحسّاسة

- [ ] اعتمادات grey-box تُخزَّن **مُشفّرة** (Fernet) عبر `/programs/{id}/credentials`.
- [ ] السر **لا يُعاد أبدًا** عبر الـ API — فقط `id` و `label`.

## 3. تحديد المعدّل (Rate limiting)

- [ ] مُفعّل افتراضيًا (`RATE_LIMIT_PER_MINUTE`, لكل IP) على كل الـ API.
- [ ] الاستجابة `429` عند التجاوز.

## 4. فرض النطاق (أساسي)

- [ ] كل هدف يمرّ عبر **Scope Gatekeeper** قبل أي فحص.
- [ ] خارج النطاق يُرفض ويُسجَّل في `audit_log`.
- [ ] **لا إرسال آلي** لـ HackerOne — التقارير مسودّات بمراجعة بشرية.

## 5. فحص تسريب الأسرار

```bash
# يتطلب تثبيت gitleaks (https://github.com/gitleaks/gitleaks)
gitleaks detect --config .gitleaks.toml --no-banner
```

- [ ] يمرّ `gitleaks` دون أي نتيجة حقيقية قبل كل دمج.

## 6. الحاويات

- [ ] `docker.sock` يُمنح للـ worker فقط في بيئة موثوقة (Strix يحتاجه للـ sandbox).
- [ ] كلمات مرور قاعدة البيانات مُغيّرة عن الافتراضي في الإنتاج.
