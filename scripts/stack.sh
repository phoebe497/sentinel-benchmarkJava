#!/usr/bin/env bash
# Single entrypoint for the Week 6 lab stack (see docker-compose.yml).
#
#   up      build + start gateway, juice-shop and demo-api (generates the key once)
#   scan    run the ZAP baseline scan against juice-shop
#   routes  print the allowlist the gateway publishes
#   logs    follow gateway logs
#   down    stop everything
#
# The API key is generated once into .env (gitignored) and never printed. The
# gateway reads GATEWAY_API_KEY; the agent's request tool reads
# SENTINEL_GATEWAY_API_KEY. Same value, two names, because they are two
# independent processes.
set -euo pipefail
cd "$(dirname "$0")/.."

ENV_FILE=.env

ensure_key() {
  if [ -f "$ENV_FILE" ] && grep -q '^GATEWAY_API_KEY=..' "$ENV_FILE"; then
    echo "[stack] reusing GATEWAY_API_KEY from $ENV_FILE"
    return
  fi
  local key
  key="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  {
    echo "GATEWAY_API_KEY=${key}"
    echo "SENTINEL_GATEWAY_API_KEY=${key}"
    echo "SENTINEL_GATEWAY_URL=http://localhost:8080"
  } >>"$ENV_FILE"
  echo "[stack] generated a fresh gateway API key -> $ENV_FILE"
}

require_submodule() {
  if [ ! -f vendor/api-gateway/gateway/app.py ]; then
    echo "[stack] vendor/api-gateway is empty. Run:" >&2
    echo "        git submodule update --init --recursive" >&2
    exit 1
  fi
}

check_port() {
  # The standalone Week 4 project publishes the same port. Two gateways on 8080
  # would silently shadow each other, so refuse instead of guessing.
  local owner
  owner="$(docker ps --filter publish=8080 --format '{{.Names}}' | grep -v '^sentinel-' || true)"
  if [ -n "$owner" ]; then
    echo "[stack] port 8080 is already taken by: $owner" >&2
    echo "        stop it first, e.g. docker stop $owner" >&2
    exit 1
  fi
}

case "${1:-up}" in
up)
  require_submodule
  check_port
  ensure_key
  mkdir -p artifacts/week-6/gateway artifacts/week-6/dast
  docker compose up -d --build
  echo "[stack] gateway on http://localhost:8080 (juice-shop and demo-api stay internal)"
  echo "[stack] next: bash scripts/stack.sh scan"
  ;;
scan)
  mkdir -p artifacts/week-6/dast
  # --rm: the scanner is a one-shot job, not a long-lived service.
  docker compose --profile scan run --rm zap
  echo "[stack] raw DAST output -> artifacts/week-6/dast/zap-baseline.json"
  # Provenance is derived from the artifact, never hand-written, so the manifest
  # cannot drift from the evidence it describes.
  python3 scripts/security/zap_dast.py
  ;;
routes)
  # Read the one variable we need instead of sourcing the file: .env may carry
  # CRLF line endings on Windows hosts, which breaks `.` sourcing.
  key="$(grep -m1 '^SENTINEL_GATEWAY_API_KEY=' "$ENV_FILE" | cut -d= -f2- | tr -d '\r\n')"
  curl -fsS -H "X-API-Key: ${key}" http://localhost:8080/_gateway/routes
  echo
  ;;
logs)
  docker compose logs -f gateway
  ;;
down)
  docker compose down
  ;;
*)
  echo "usage: $0 {up|scan|routes|logs|down}" >&2
  exit 2
  ;;
esac
