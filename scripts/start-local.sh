#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose stop hiro-proxy frontend >/dev/null 2>&1 || true
docker compose build hiro-proxy frontend
docker compose run --rm --no-deps hiro-proxy --migrate-only
docker compose up -d --no-build hiro-proxy frontend
