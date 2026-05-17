#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ADAPTER="mcp"
RUN_SETUP=1
ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
RESOURCE_URL="${RESOURCE_URL:-http://localhost:8080/mcp}"

usage() {
  cat <<'EOF'
Usage:
  manual-e2e-smoke.sh [--adapter mcp|http] [--skip-setup]
EOF
}

while [ "${#}" -gt 0 ]; do
  case "$1" in
    --adapter)
      ADAPTER="${2:-}"
      shift
      ;;
    --skip-setup)
      RUN_SETUP=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [ "${ADAPTER}" = "mcp" ]; then
  RUN_CMD="./mcp/demo/run.sh"
elif [ "${ADAPTER}" = "http" ]; then
  RUN_CMD="./http/demo/run.sh"
else
  echo "Invalid adapter: ${ADAPTER}" >&2
  exit 1
fi

SERVER_LOG="/tmp/go-adapters-manual-e2e-smoke-${ADAPTER}.log"
PRM_URL="${RESOURCE_URL%/mcp}/.well-known/oauth-protected-resource/mcp"

cleanup() {
  if [ -n "${SERVER_PID:-}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" || true
  fi
}
trap cleanup EXIT

if [ "${RUN_SETUP}" -eq 1 ]; then
  bash "${SCRIPT_DIR}/manual-e2e-setup.sh"
fi

echo "==> Starting Go demo (${ADAPTER})"
(
  cd "${REPO_ROOT}"
  ${RUN_CMD} >"${SERVER_LOG}" 2>&1
) &
SERVER_PID=$!

echo "==> Waiting for PRM: ${PRM_URL}"
for _ in $(seq 1 45); do
  status="$(curl -sS -o /dev/null -w "%{http_code}" "${PRM_URL}" || true)"
  if [ "${status}" = "200" ] || [ "${status}" = "401" ]; then
    break
  fi
  sleep 1
done
status="$(curl -sS -o /dev/null -w "%{http_code}" "${PRM_URL}" || true)"
if [ "${status}" != "200" ] && [ "${status}" != "401" ]; then
  echo "ERROR: PRM endpoint not ready (status=${status})" >&2
  echo "Server log: ${SERVER_LOG}" >&2
  exit 1
fi

if [ ! -f /tmp/authserver-demo.client-id ] || [ ! -f /tmp/authserver-demo.key ]; then
  echo "ERROR: missing /tmp/authserver-demo.client-id or /tmp/authserver-demo.key" >&2
  exit 1
fi

CLIENT_ID="$(cat /tmp/authserver-demo.client-id)"
CLIENT_SECRET="$(cat /tmp/authserver-demo.key)"

echo "==> Minting token (tools/add)"
TOKEN_JSON="$(
  curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "resource=${RESOURCE_URL}" \
    -d "scope=tools/add" \
    "${ISSUER_URL}/oauth/token"
)"

TOKEN_ERROR="$(
  echo "${TOKEN_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("error",""))'
)"
if [ "${TOKEN_ERROR}" = "invalid_scope" ]; then
  TOKEN_JSON="$(
    curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=client_credentials" \
      -d "resource=${RESOURCE_URL}" \
      "${ISSUER_URL}/oauth/token"
  )"
fi

ACCESS_TOKEN="$(
  echo "${TOKEN_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))'
)"
if [ -z "${ACCESS_TOKEN}" ]; then
  echo "ERROR: token mint failed" >&2
  echo "${TOKEN_JSON}" >&2
  exit 1
fi

if [ "${ADAPTER}" = "mcp" ]; then
  echo "==> Checking unauthenticated /mcp is blocked"
  status_noauth="$(
    curl -sS -o /dev/null -w "%{http_code}" -X POST "${RESOURCE_URL}" \
      -H "Content-Type: application/json" \
      -d '{}' || true
  )"
else
  echo "==> Checking unauthenticated /mcp/add is blocked"
  status_noauth="$(
    curl -sS -o /dev/null -w "%{http_code}" -X POST "${RESOURCE_URL%/mcp}/mcp/add" \
      -H "Content-Type: application/json" \
      -d '{"a":1,"b":2}' || true
  )"
fi

if [ "${status_noauth}" = "200" ]; then
  echo "ERROR: unauthenticated request unexpectedly returned 200" >&2
  exit 1
fi

echo ""
echo "Smoke check passed (go-adapters, adapter=${ADAPTER})"
echo "PRM: ${PRM_URL}"
echo "Server log: ${SERVER_LOG}"
