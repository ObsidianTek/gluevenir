#!/bin/sh
set -eu

admin_password="$(tr -d '-' </proc/sys/kernel/random/uuid)"
export GF_SECURITY_ADMIN_PASSWORD="$admin_password"
export GF_SECURITY_ADMIN_USER=admin

/run.sh &
grafana_pid=$!

cleanup() {
  kill -TERM "$grafana_pid" 2>/dev/null || true
  wait "$grafana_pid" 2>/dev/null || true
}
trap cleanup INT TERM

attempt=0
until wget -q -O /dev/null http://127.0.0.1:3000/api/health; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo "grafana health timeout" >&2
    cleanup
    exit 1
  fi
  sleep 1
done

auth="$(printf 'admin:%s' "$admin_password" | base64 | tr -d '\n')"
publish_dashboard() {
  dashboard_uid="$1"
  public_uid="$2"
  access_token="$3"
  endpoint="http://127.0.0.1:3000/api/dashboards/uid/${dashboard_uid}/public-dashboards"
  attempt=0
  until wget -q -O /dev/null --header="Authorization: Basic ${auth}" \
    "http://127.0.0.1:3000/api/dashboards/uid/${dashboard_uid}"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
      echo "provisioned dashboard unavailable" >&2
      cleanup
      exit 1
    fi
    sleep 1
  done
  # Grafana's shared-dashboard API is slash-sensitive. Without the trailing
  # slash, Grafana redirects to an application route that can return 200 even
  # when no public share exists.
  if wget -q -O /dev/null --header="Authorization: Basic ${auth}" "${endpoint}/"; then
    return 0
  fi
  payload="{\"uid\":\"${public_uid}\",\"accessToken\":\"${access_token}\",\"timeSelectionEnabled\":true,\"isEnabled\":true,\"annotationsEnabled\":false,\"share\":\"public\"}"
  wget -q -O /dev/null \
    --header="Authorization: Basic ${auth}" \
    --header="Content-Type: application/json" \
    --post-data="$payload" \
    "${endpoint}/"
}

publish_dashboard gluevenir-local-telemetry 10886e17-289a-5c7e-b1ce-d7ec70a8ce27 9e978d5eafa627ea61946044a80f3a41
publish_dashboard gv-persona-program-lead 7b7dff1b-b937-56fd-94b6-09d1fcb56406 9ab2bc2d01e29b2c642e14ccba48b9de
publish_dashboard gv-persona-formulation-scientist 24234855-d7e3-5ebf-9b26-dcb5265b3b5b df2d55ae6508a21e8f5f0a083cb455ed
publish_dashboard gv-persona-clinical-ops-lead 38e65b2d-f237-5e94-b742-5d9c7c3fda85 ba2e6408c254887fc6567c71efa533f0
publish_dashboard gv-persona-external-partner 3c2d9e91-33d6-5bca-9409-21bf05671670 e8827e00c81371176c524f34461e67d8

wait "$grafana_pid"
