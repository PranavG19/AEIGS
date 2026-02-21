#!/usr/bin/env bash
set -euo pipefail

TARGET_PORT="${TARGET_PORT:-9999}"
BOT_PORT="${BOT_PORT:-8082}"

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

echo "--- Starting bot detection ---"
TARGET_PORT=${TARGET_PORT} docker compose up -d --build --wait

echo "--- Test: browser-like request should pass ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "User-Agent: Mozilla/5.0 Chrome/120.0" \
    -H "Accept: text/html" \
    -H "Accept-Language: en-US" \
    -H "Accept-Encoding: gzip" \
    "http://localhost:${BOT_PORT}/")
[ "$STATUS" = "200" ] && echo "PASS: browser request returned $STATUS" || echo "WARN: expected 200 got $STATUS"

echo "--- Test: empty UA should be blocked ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: " "http://localhost:${BOT_PORT}/")
[ "$STATUS" = "403" ] && echo "PASS: bot blocked with $STATUS" || echo "WARN: expected 403 got $STATUS"

echo "--- Tearing down ---"
docker compose down -t 1
echo "DONE"
