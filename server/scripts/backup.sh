#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; set -a; source "$ROOT/.env"; set +a
DIR="${BACKUP_DIR:-$ROOT/backups}"; mkdir -p "$DIR"; STAMP="$(date +%Y%m%d-%H%M%S)"; FILE="$DIR/kpi_portal-$STAMP.sql"
MYSQL_PWD="${DB_PASSWORD:-}" mysqldump --host="${DB_HOST:-127.0.0.1}" --port="${DB_PORT:-3306}" --user="$DB_USER" --single-transaction --routines --triggers --events --databases "$DB_NAME" > "$FILE"
find "$DIR" -name '*.sql' -type f -mtime +"${BACKUP_RETENTION_DAYS:-30}" -delete
echo "Backup created: $FILE"
