# النشر (Deployment)

## أمر النشر الواحد

```bash
make deploy
```

يسوّي: تهيئة `.env` + مفتاح التشفير، ثم بناء وتشغيل كل الخدمات. بعدها افتح
**http://localhost:8000/** للوحة التحكم.

بدون `make`:
```bash
python scripts/init_env.py
docker compose -f docker/docker-compose.yml up --build -d
```

## الخدمات

| الخدمة | الدور |
|---|---|
| `api` | FastAPI + لوحة التحكم (منفذ 8000) |
| `worker` | عمّال Celery (recon / scan / strix) |
| `beat` | الجدولة الدورية |
| `postgres` | قاعدة البيانات |
| `redis` | الطابور + قفل التزامن |

## قبل الإنتاج

1. **غيّر كلمة مرور قاعدة البيانات** في `.env` (`POSTGRES_PASSWORD`).
2. **عيّن `FIELD_ENCRYPTION_KEY`** (يفعله `scripts/init_env.py`) واحتفظ بنسخة آمنة.
3. **مفاتيح LLM/HackerOne** في `.env` فقط (انظر `docs/SECURITY.md`).
4. طبّق المخطط عبر migrations:
   ```bash
   docker compose -f docker/docker-compose.yml exec api python -m alembic upgrade head
   ```

## التوسّع

- **استخدام بسيط إلى متوسط:** docker-compose كافٍ. زد عمّال الفحص:
  ```bash
  docker compose -f docker/docker-compose.yml up -d --scale worker=3
  ```
- **استخدام كبير:** انقل إلى Kubernetes (Deployments لـ api/worker/beat + StatefulSets
  لـ postgres/redis). قفل التزامن عبر Redis يعمل عبر عدة عمّال بلا تغيير.

## CI

`.github/workflows/ci.yml` يشغّل على كل push/PR: `ruff` + `pytest` + `gitleaks`.
