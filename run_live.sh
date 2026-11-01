#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=== Starting PinHire Guard Webhook (PH-2026-4061) ==="
echo "Seed Token: SEED-4061-PH-CCE6"
echo "Header: x-pinhire-hmac-4061"
echo "Max Refund: 175 AED"
echo "Idempotency TTL: 240s"

# Kill existing on 8000 if any
lsof -ti:8000 | xargs kill -9 2>/dev/null || true

# Start FastAPI server
echo "Starting local server on port 8000..."
uv run --with fastapi --with "uvicorn[standard]" python3 app.py &
SERVER_PID=$!

trap "kill $SERVER_PID 2>/dev/null || true; exit 0" INT TERM EXIT

sleep 2

# Start localhost.run tunnel
echo "Starting public HTTPS tunnel via localhost.run..."
ssh -o StrictHostKeyChecking=no -R 80:localhost:8000 nokey@localhost.run
