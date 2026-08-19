#!/bin/sh
set -eu

retention_time="${GLUEVENIR_RETENTION_TIME:-24h}"
retention_size="${GLUEVENIR_RETENTION_SIZE:-1GB}"

case "$retention_time" in
  24h) ;;
  *) echo "unsupported bounded retention time" >&2; exit 64 ;;
esac
case "$retention_size" in
  1GB) ;;
  *) echo "unsupported bounded retention size" >&2; exit 64 ;;
esac

exec /bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/prometheus \
  --storage.tsdb.retention.time="$retention_time" \
  --storage.tsdb.retention.size="$retention_size" \
  --no-web.enable-admin-api \
  --no-web.enable-lifecycle \
  --web.listen-address=127.0.0.1:9090 \
  --log.level=warn
