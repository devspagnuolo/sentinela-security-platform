#!/bin/sh
# Backup lógico do PostgreSQL (pg_dump em formato custom), com retenção em dias.
#   backup.sh once  → um backup agora
#   backup.sh loop  → um backup por dia (usado pelo serviço "backup" do compose)
# Restauração: pg_restore --clean --if-exists -d sentinela /backups/<arquivo>.dump
set -eu

run_backup() {
  file="/backups/sentinela-$(date -u +%Y%m%dT%H%M%SZ).dump"
  pg_dump --format=custom --no-owner --file="$file.partial"
  mv "$file.partial" "$file"
  find /backups -name 'sentinela-*.dump' -mtime +"${BACKUP_RETENTION_DAYS:-14}" -delete
  echo "{\"time\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"level\":\"info\",\"msg\":\"backup.completed\",\"file\":\"$file\"}"
}

case "${1:-once}" in
  once) run_backup ;;
  loop)
    while true; do
      run_backup || echo "{\"level\":\"error\",\"msg\":\"backup.failed\"}" >&2
      sleep 86400
    done ;;
  *) echo "uso: backup.sh once|loop" >&2; exit 1 ;;
esac
