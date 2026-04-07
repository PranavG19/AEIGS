#!/bin/bash
# AEGIS ARENA DAEMON — keeps aegis-arena --infinite running forever
# Usage: ./arena-daemon.sh
# Monitor: tmux attach -t aegis-arena
# Stop: touch .arena-stop

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SESSION="aegis-arena"
LOG_DIR="$PROJECT_DIR/.arena-logs"
STOP_FILE="$PROJECT_DIR/.arena-stop"
BINARY="$PROJECT_DIR/target/debug/aegis-arena"
ITERATION=0

mkdir -p "$LOG_DIR"
rm -f "$STOP_FILE"
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Export creds
export AWS_PROFILE=ziya
AWS_CREDS=$(aws configure export-credentials --format env 2>/dev/null) || true
[ -n "$AWS_CREDS" ] && eval "$AWS_CREDS"

CLEAN_PATH=$(echo "$PATH" | tr ':' '\n' | grep -v "Visual Studio Code" | tr '\n' ':' | sed 's/:$//')

# Write inner loop script
LOOP="$LOG_DIR/.arena_loop.sh"
cat > "$LOOP" << 'INNER'
#!/bin/bash
PROJECT_DIR="__PROJECT_DIR__"
LOG_DIR="$PROJECT_DIR/.arena-logs"
STOP_FILE="$PROJECT_DIR/.arena-stop"
BINARY="$PROJECT_DIR/target/debug/aegis-arena"
ITERATION=0

echo "═══════════════════════════════════════"
echo "  AEGIS ARENA DAEMON"
echo "  Infinite Red vs Blue Evolution"
echo "  Stop: touch .arena-stop"
echo "═══════════════════════════════════════"

while true; do
  ITERATION=$((ITERATION + 1))
  TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
  LOG="$LOG_DIR/run_${ITERATION}_${TIMESTAMP}.log"

  [ -f "$STOP_FILE" ] && echo "Stop signal. Exiting." && rm -f "$STOP_FILE" && break

  echo ""
  echo "━━━ Arena Run $ITERATION | $TIMESTAMP ━━━"
  echo "Starting aegis-arena --infinite --watch..."

  "$BINARY" --infinite --watch --speed fast 2>&1 | tee "$LOG"
  EXIT=$?

  echo ""
  echo "Arena exited (code=$EXIT). Restarting in 10s..."
  echo "Check last log: $LOG"
  sleep 10
done
INNER

sed -i '' "s|__PROJECT_DIR__|$PROJECT_DIR|g" "$LOOP"
chmod +x "$LOOP"

tmux new-session -d -s "$SESSION" -c "$PROJECT_DIR" \
  -e "AWS_PROFILE=ziya" \
  -e "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}" \
  -e "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}" \
  -e "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN:-}" \
  "unset VISUAL; unset EDITOR; export PATH=\"$CLEAN_PATH\"; bash \"$LOOP\""

echo "═══════════════════════════════════════"
echo "  AEGIS ARENA DAEMON launched"
echo "  Session: $SESSION"
echo "  Logs: $LOG_DIR/"
echo "═══════════════════════════════════════"
echo ""
echo "  Watch:  tmux attach -t $SESSION"
echo "  Stop:   touch .arena-stop"
echo "  Logs:   ls -la .arena-logs/"
