#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

exec uv run --frozen uvicorn responder.main:app \
  --app-dir incident-response \
  --host 127.0.0.1 \
  --port "${INCIDENT_RESPONSE_PORT:-8001}"
