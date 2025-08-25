#!/usr/bin/env bash

set -euo pipefail

URL="${URL:-http://localhost:3000/api/graphql}"
DISPLAY_NAME="${DISPLAY_NAME:-ATEXO Stagiaires}"
# Prefer environment-provided values if present (from docker-compose `environment:`)
HOST="${HOST:-${DB_HOST:-}}"
PORT="${PORT:-${DB_PORT:-3306}}"
DB_USER="${DB_USER:-${DB_USER:-}}"
DB_PASSWORD="${DB_PASSWORD:-${DB_PASSWORD:-}}"
DATABASE="${DATABASE:-${DB_NAME:-}}"
SSL_RAW="${SSL:-${DB_SSL:-false}}" # accepts: true/false/1/0/yes/no
COOKIE="${COOKIE:-}"    # optional raw Cookie header value
DEBUG="${DEBUG:-0}"
RETRY_ON_EMPTY_REPLY="${RETRY_ON_EMPTY_REPLY:-3}"
RETRY_ON_READONLY_DB="${RETRY_ON_READONLY_DB:-3}"
RETRY_BACKOFF_SECONDS="${RETRY_BACKOFF_SECONDS:-10}"

print_usage() {
  echo "Usage: $0 --host HOST --port PORT --user USER --password PASS --database DB [options]" >&2
  echo "Options:" >&2
  echo "  --url URL                GraphQL endpoint (default: $URL)" >&2
  echo "  --display-name NAME     Data source display name (default: $DISPLAY_NAME)" >&2
  echo "  --ssl BOOL              Enable SSL (true/false/1/0/yes/no). Default: $SSL" >&2
  echo "  --cookie STRING         Cookie header value to include (optional)" >&2
  echo "  -h, --help              Show this help" >&2
}

to_bool() {
  case "${1,,}" in
    true|1|yes|y) echo true ;;
    false|0|no|n|"") echo false ;;
    *) echo "Invalid boolean: $1" >&2; exit 1 ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --display-name) DISPLAY_NAME="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --user) DB_USER="$2"; shift 2 ;;
    --password) DB_PASSWORD="$2"; shift 2 ;;
    --database) DATABASE="$2"; shift 2 ;;
    --ssl) SSL_RAW="$2"; shift 2 ;;
    --cookie) COOKIE="$2"; shift 2 ;;
    -h|--help) print_usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; print_usage; exit 1 ;;
  esac
done

# Validate required args
SSL="$(to_bool "$SSL_RAW")"

if [[ "$DEBUG" == "1" ]]; then
  echo "[DEBUG] Using parameters:" >&2
  echo "  URL=$URL" >&2
  echo "  DISPLAY_NAME=$DISPLAY_NAME" >&2
  echo "  HOST=${HOST:-<empty>}" >&2
  echo "  PORT=${PORT:-<empty>}" >&2
  echo "  DB_USER=${DB_USER:-<empty>}" >&2
  echo "  DB_PASSWORD=${DB_PASSWORD:+<set>}" >&2
  echo "  DATABASE=${DATABASE:-<empty>}" >&2
  echo "  SSL=$SSL (raw: $SSL_RAW)" >&2
fi

missing=()
[[ -z "$HOST" ]] && missing+=(--host)
[[ -z "$PORT" ]] && missing+=(--port)
[[ -z "$DB_USER" ]] && missing+=(--user)
[[ -z "$DB_PASSWORD" ]] && missing+=(--password)
[[ -z "$DATABASE" ]] && missing+=(--database)
if (( ${#missing[@]} > 0 )); then
  echo "Missing required arguments: ${missing[*]}" >&2
  print_usage
  exit 1
fi

build_payload_with_jq() {
  jq -n \
    --arg displayName "$DISPLAY_NAME" \
    --arg host "$HOST" \
    --arg port "$PORT" \
    --arg user "$DB_USER" \
    --arg password "$DB_PASSWORD" \
    --arg database "$DATABASE" \
    --arg query 'mutation UpdateDataSource($data: UpdateDataSourceInput!) {  updateDataSource(data: $data) {    type    properties    __typename  }}' \
    --arg op 'UpdateDataSource' \
    --argjson ssl $SSL \
    '{operationName:$op, variables:{data:{properties:{displayName:$displayName,host:$host,port:$port,user:$user,password:$password,database:$database,ssl:$ssl}}}, query:$query}'
}

build_payload_plain() {
  # Plain builder (less safe). Avoid quotes in values when using this path.
  cat <<EOF
{"operationName":"UpdateDataSource","variables":{"data":{"properties":{"displayName":"$DISPLAY_NAME","host":"$HOST","port":"$PORT","user":"$DB_USER","password":"$DB_PASSWORD","database":"$DATABASE","ssl":$SSL}}},"query":"mutation UpdateDataSource($data: UpdateDataSourceInput!) {  updateDataSource(data: $data) {    type    properties    __typename  }}"}
EOF
}

if command -v jq >/dev/null 2>&1; then
  DATA_PAYLOAD=$(build_payload_with_jq)
else
  DATA_PAYLOAD=$(build_payload_plain)
fi

curl_args=(
  -sS
  -X POST
  "$URL"
  -H 'content-type: application/json'
  -H 'accept: */*'
  --data-raw "$DATA_PAYLOAD"
)

if [[ -n "$COOKIE" ]]; then
  curl_args+=( -H "Cookie: $COOKIE" )
fi

attempt=0
while true; do
  set +e
  RESPONSE=$(curl "${curl_args[@]}")
  CURL_EXIT=$?
  set -e

  if [[ $CURL_EXIT -eq 0 ]]; then
    # Check GraphQL response for specific readonly DB error; retry if found
    if command -v jq >/dev/null 2>&1; then
      readonly_err=$(printf '%s' "$RESPONSE" | jq -r '(.errors // []) | map(.message // .extensions.message // "") | map(select(test("readonly database"; "i"))) | length')
    else
      # Fallback: simple grep if jq missing
      echo "$RESPONSE" | grep -qi "readonly database" && readonly_err=1 || readonly_err=0
    fi

    if [[ "${readonly_err:-0}" -gt 0 && $attempt -lt $RETRY_ON_READONLY_DB ]]; then
      echo "GraphQL error indicates readonly database. Retrying in ${RETRY_BACKOFF_SECONDS}s... (attempt $((attempt+1))/$RETRY_ON_READONLY_DB)" >&2
      attempt=$((attempt+1))
      sleep "$RETRY_BACKOFF_SECONDS"
      continue
    fi

    echo "$RESPONSE"
    break
  fi

  if [[ $CURL_EXIT -eq 52 && $attempt -lt $RETRY_ON_EMPTY_REPLY ]]; then
    echo "Received curl error 52 (Empty reply). Retrying in ${RETRY_BACKOFF_SECONDS}s... (attempt $((attempt+1))/$RETRY_ON_EMPTY_REPLY)" >&2
    attempt=$((attempt+1))
    sleep "$RETRY_BACKOFF_SECONDS"
    continue
  fi

  echo "$RESPONSE" >&2
  exit $CURL_EXIT
done


