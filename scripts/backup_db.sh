#!/usr/bin/env bash
# نسخة احتياطية دورية لـ Postgres مع احتفاظ (retention).
# الاستخدام:  bash scripts/backup_db.sh    (أو عبر cron / make backup)
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
COMPOSE="docker compose -f docker/docker-compose.yml"

# حمّل متغيرات .env إن وُجد (POSTGRES_USER / POSTGRES_DB).
[ -f .env ] && set -a && . ./.env && set +a

mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/iqscan-$STAMP.sql.gz"

$COMPOSE exec -T postgres pg_dump -U "${POSTGRES_USER:-strix}" "${POSTGRES_DB:-strix}" | gzip > "$OUT"
echo "✓ نسخة احتياطية: $OUT"

# حذف النسخ الأقدم من RETENTION_DAYS يومًا.
find "$BACKUP_DIR" -name 'iqscan-*.sql.gz' -mtime +"$RETENTION_DAYS" -delete
echo "✓ احتفاظ: حُذفت النسخ الأقدم من $RETENTION_DAYS يومًا"

# الاستعادة:
#   gunzip -c backups/iqscan-XXXX.sql.gz | \
#     docker compose -f docker/docker-compose.yml exec -T postgres \
#     psql -U "$POSTGRES_USER" "$POSTGRES_DB"
