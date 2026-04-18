#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

python3 -m venv "$ROOT_DIR/.venv"
source "$ROOT_DIR/.venv/bin/activate"
pip install --upgrade pip
pip install -r "$BACKEND_DIR/requirements.txt"

echo "Starting FastAPI backend on http://127.0.0.1:8000"
(
  cd "$BACKEND_DIR"
  uvicorn main:app --host 127.0.0.1 --port 8000 --reload
) &
BACKEND_PID=$!

echo "Starting frontend on http://127.0.0.1:8080"
(
  cd "$FRONTEND_DIR"
  python3 -m http.server 8080
) &
FRONTEND_PID=$!

cleanup() {
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait
