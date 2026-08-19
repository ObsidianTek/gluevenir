#!/bin/sh
set -eu

max_traces="${MEMORY_MAX_TRACES:-5000}"
max_lifetime_seconds="${GLUEVENIR_TRACE_MAX_LIFETIME_SECONDS:-86400}"
case "$max_traces" in
  5000) ;;
  *) echo "unsupported bounded trace capacity" >&2; exit 64 ;;
esac
case "$max_lifetime_seconds" in
  86400) ;;
  *) echo "unsupported bounded trace lifetime" >&2; exit 64 ;;
esac

# The explicit v2 config enables only the task-local OTLP HTTP receiver used by
# the Collector. ECS maps no trace-ingest port and Viewer never proxies it.
export MEMORY_MAX_TRACES="$max_traces"
exec timeout -s TERM -k 30 "$max_lifetime_seconds" \
  /cmd/jaeger/jaeger-linux --config=/etc/jaeger/config.yaml
