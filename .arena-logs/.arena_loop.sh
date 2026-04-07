#!/bin/bash
PROJECT_DIR="/Users/pranavgk/Documents/temp/adver"
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
