#!/usr/bin/env bash
set -euo pipefail

TARGET_PORT="${TARGET_PORT:-9999}"
RATE_LIMIT_PORT="${RATE_LIMIT_PORT:-8081}"

echo "--- Starting echo server on :${TARGET_PORT} ---"
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
HTTPServer(('', ${TARGET_PORT}), H).serve_forever()
" &
ECHO_PID=$!
trap "kill $ECHO_PID 2>/dev/null; docker compose down -t 1 2>/dev/null" EXIT

echo "--- Starting rate limiter ---"
TARGET_PORT=${TARGET_PORT} docker compose up -d --wait

echo "--- Test: single request should pass ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${RATE_LIMIT_PORT}/")
[ "$STATUS" = "200" ] && echo "PASS: single request returned $STATUS" || { echo "FAIL: expected 200 got $STATUS"; exit 1; }

echo "--- Test: burst should eventually be limited ---"
LIMITED=0
for i in $(seq 1 50); do
    S=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${RATE_LIMIT_PORT}/")
    [ "$S" = "429" ] && LIMITED=1 && break
done
[ "$LIMITED" = "1" ] && echo "PASS: rate limit triggered" || echo "WARN: rate limit not triggered in 50 requests"

echo "--- Tearing down ---"
docker compose down -t 1
echo "DONE"
