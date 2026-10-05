#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

response_host=${INCIDENT_RESPONSE_HOST:-127.0.0.1}

if [ -f "$project_dir/.env" ]; then
  exec uv run --env-file "$project_dir/.env" --frozen uvicorn responder.main:app \
    --app-dir incident-response \
    --host "$response_host" \
    --port "${INCIDENT_RESPONSE_PORT:-8001}"
fi

exec uv run --frozen uvicorn responder.main:app \
  --app-dir incident-response \
  --host "$response_host" \
  --port "${INCIDENT_RESPONSE_PORT:-8001}"
