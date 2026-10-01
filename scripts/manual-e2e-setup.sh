#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AUTHSERVER_DIR="${AUTHSERVER_DIR:-$REPO_ROOT/../authserver}"

usage() {
  cat <<'EOF'
Usage:
  manual-e2e-setup.sh

Environment (optional):
  AUTHSERVER_DIR   Path to local authserver repo (default: ../authserver)
  AUTHSERVER_REF   Git ref of authserver to check out before building
                   (default: leave the checkout as is)
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ ! -d "${AUTHSERVER_DIR}" ]; then
  echo "ERROR: authserver repo not found at ${AUTHSERVER_DIR}" >&2
  exit 1
fi

echo "==> Starting authserver demo server"
(
  cd "${AUTHSERVER_DIR}"
  if [ -n "${AUTHSERVER_REF:-}" ]; then
    echo "==> Checking out authserver ${AUTHSERVER_REF}"
    git fetch --tags origin || echo "WARN: fetch failed, resolving ${AUTHSERVER_REF} from local refs" >&2
    git checkout "${AUTHSERVER_REF}"
    rm -f bin/authserver
  fi
  if [ ! -x "bin/authserver" ]; then
    go build -o bin/authserver ./cmd/authserver
  fi
  ./demo/mcp-demo-server-start.sh
)

echo ""
echo "Setup completed."
