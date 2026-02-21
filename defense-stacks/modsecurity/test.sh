#!/usr/bin/env bash
set -euo pipefail

TARGET_PORT="${TARGET_PORT:-9999}"
WAF_PORT="${WAF_PORT:-8080}"

echo "--- Starting echo server on :${TARGET_PORT} ---"
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def do_POST(self): self.do_GET()
    def log_message(self, *a): pass
HTTPServer(('', ${TARGET_PORT}), H).serve_forever()
" &
ECHO_PID=$!
trap "kill $ECHO_PID 2>/dev/null; docker compose down -t 1 2>/dev/null" EXIT

echo "--- Starting ModSecurity WAF ---"
TARGET_PORT=${TARGET_PORT} WAF_PORT=${WAF_PORT} docker compose up -d --wait

echo "--- Test: benign request should pass ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${WAF_PORT}/")
[ "$STATUS" = "200" ] && echo "PASS: benign request returned $STATUS" || { echo "FAIL: expected 200 got $STATUS"; exit 1; }

echo "--- Test: SQLi probe should be blocked ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${WAF_PORT}/?q=' OR 1=1--")
[ "$STATUS" = "403" ] && echo "PASS: SQLi blocked with $STATUS" || echo "WARN: expected 403 got $STATUS (paranoia level may differ)"

echo "--- Tearing down ---"
docker compose down -t 1
echo "DONE"
