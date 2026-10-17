# IQScan — أوامر مختصرة. استخدم: make <target>
COMPOSE = docker compose -f docker/docker-compose.yml

.PHONY: help init deploy up down logs test lint migrate scan-secrets

help:            ## عرض الأوامر
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

init:            ## تهيئة .env + مفتاح التشفير
	python scripts/init_env.py

deploy: init     ## نشر نسخة كاملة شغّالة (أمر واحد)
	$(COMPOSE) up --build -d
	@echo "✓ IQScan شغّال — افتح http://localhost:8000/"

up:              ## تشغيل الخدمات
	$(COMPOSE) up -d

down:            ## إيقاف الخدمات
	$(COMPOSE) down

logs:            ## متابعة السجلّات
	$(COMPOSE) logs -f

test:            ## تشغيل الاختبارات
	pytest -q

lint:            ## فحص الجودة
	ruff check .

migrate:         ## تطبيق migrations
	python -m alembic upgrade head

scan-secrets:    ## فحص تسريب الأسرار (يتطلب gitleaks)
	gitleaks detect --config .gitleaks.toml --no-banner

backup:          ## نسخة احتياطية لقاعدة البيانات (مع retention)
	bash scripts/backup_db.sh
