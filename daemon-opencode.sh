#!/bin/bash
# AEGIS DAEMON v3 | opencode-powered | bash loop in tmux
#
# Run:     ./daemon-opencode.sh
# Monitor: tmux attach -t aegis-daemon
# Stop:    touch .claude/daemon/STOP  (daemon checks each iteration)
# Kill:    tmux kill-session -t aegis-daemon

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
DAEMON_DIR="$PROJECT_ROOT/.claude/daemon"
LOG_DIR="$DAEMON_DIR/logs"
STATE_FILE="$DAEMON_DIR/STATE.md"
PROMPT_FILE="$DAEMON_DIR/PROMPT.md"
STOP_FILE="$DAEMON_DIR/STOP"
SESSION_NAME="aegis-daemon"
ITERATION=0

# ── CONFIG ──────────────────────────────────────────────────────────
MODEL="${AEGIS_MODEL:-amazon-bedrock/global.anthropic.claude-opus-4-6-v1}"
AGENT="build"
COOLDOWN=10        # seconds between iterations
MAX_ITERATIONS=0   # 0 = infinite

# ── PRE-FLIGHT ──────────────────────────────────────────────────────
mkdir -p "$LOG_DIR" "$DAEMON_DIR"
for cmd in opencode git tmux; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "FATAL: $cmd not found"; exit 1; }
done
[ -f "$PROJECT_ROOT/CLAUDE.md" ] || { echo "FATAL: no CLAUDE.md"; exit 1; }
[ -f "$PROMPT_FILE" ]            || { echo "FATAL: no $PROMPT_FILE"; exit 1; }
[ -f "$STATE_FILE" ]             || { echo "FATAL: no $STATE_FILE"; exit 1; }

# ── CLEAN UP ────────────────────────────────────────────────────────
rm -f "$STOP_FILE"
find "$LOG_DIR" -name "*.log" -mtime +3 -delete 2>/dev/null || true

# ── RESOLVE AWS CREDENTIALS ────────────────────────────────────────
export AWS_PROFILE=ziya
AWS_CREDS=$(aws configure export-credentials --format env 2>/dev/null) || true
if [ -n "$AWS_CREDS" ]; then
  eval "$AWS_CREDS"
  echo "AWS credentials resolved: $(aws sts get-caller-identity --query Arn --output text 2>/dev/null)"
else
  echo "WARNING: could not export AWS credentials — Bedrock calls may fail"
fi

# ── KILL PREVIOUS SESSION ──────────────────────────────────────────
tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
sleep 1

# ── THE DAEMON LOOP ────────────────────────────────────────────────
# This function runs inside tmux. Each iteration:
# 1. Check for STOP file
# 2. Read STATE.md to build the task prompt
# 3. Call opencode run with the task
# 4. Log output
# 5. Cooldown
# 6. Repeat

daemon_loop() {
  cd "$PROJECT_ROOT"
  
  echo "═══════════════════════════════════════════════════"
  echo "  AEGIS DAEMON v3 — opencode-powered"
  echo "  Model: $MODEL"
  echo "  Agent: $AGENT"
  echo "  Project: $PROJECT_ROOT"
  echo "═══════════════════════════════════════════════════"
  echo ""
  
  while true; do
    ITERATION=$((ITERATION + 1))
    TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
    LOG_FILE="$LOG_DIR/iteration_${ITERATION}_${TIMESTAMP}.log"
    
    # ── STOP CHECK ──
    if [ -f "$STOP_FILE" ]; then
      echo "[$TIMESTAMP] STOP file detected. Daemon halting gracefully."
      rm -f "$STOP_FILE"
      break
    fi
    
    # ── MAX ITERATIONS CHECK ──
    if [ "$MAX_ITERATIONS" -gt 0 ] && [ "$ITERATION" -gt "$MAX_ITERATIONS" ]; then
      echo "[$TIMESTAMP] Max iterations ($MAX_ITERATIONS) reached. Stopping."
      break
    fi
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ITERATION $ITERATION — $TIMESTAMP"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # ── BUILD TASK PROMPT ──
    # The prompt tells opencode to read STATE.md and execute.
    # PROMPT.md content is in CLAUDE.md / SYSTEM_PROMPT.md (auto-loaded by opencode).
    # We keep the per-iteration message small and focused.
    TASK_PROMPT="Read .claude/daemon/STATE.md and .claude/daemon/PROMPT.md. Then IMMEDIATELY start writing code.

CRITICAL: Do NOT spend more than 2 minutes reading files. You already know the codebase from CLAUDE.md. Read STATE.md for the current task, skim PROMPT.md for gates, then START CODING.

Execute the handoff task in STATE.md. Write code FIRST, explore SECOND.

Per-unit workflow: write code → cargo test -p {crate} → git add + commit '[component] verb' → update STATE.md.

If you finish the current task, move to the next sub-priority in the phase.
If you finish the phase, move to the next phase.
If all phases done, enter INFINITE ROI LOOP (see PROMPT.md).

Before context fills: write a PRECISE handoff in STATE.md (exact file, exact line, exact next action).
BIAS FOR ACTION. Ship code. No analysis paralysis."
    
    # ── EXECUTE ──
    echo "[$TIMESTAMP] Launching opencode run..."
    opencode run \
      --dir "$PROJECT_ROOT" \
      --model "$MODEL" \
      --agent "$AGENT" \
      "$TASK_PROMPT" \
      2>&1 | tee "$LOG_FILE"
    
    EXIT_CODE=$?
    echo ""
    echo "[$TIMESTAMP] Iteration $ITERATION completed (exit=$EXIT_CODE)"
    
    # ── LOG SUMMARY ──
    if [ -f "$STATE_FILE" ]; then
      echo "[$TIMESTAMP] Current state:"
      head -10 "$STATE_FILE"
    fi
    
    # ── COOLDOWN ──
    echo "[$TIMESTAMP] Cooling down ${COOLDOWN}s..."
    sleep "$COOLDOWN"
  done
  
  echo ""
  echo "═══════════════════════════════════════════════════"
  echo "  DAEMON STOPPED — Iteration $ITERATION"
  echo "═══════════════════════════════════════════════════"
}

# ── LAUNCH IN TMUX ──────────────────────────────────────────────────
# Export everything the daemon loop needs, then run it in tmux.
CLEAN_PATH=$(echo "$PATH" | tr ':' '\n' | grep -v "Visual Studio Code" | tr '\n' ':' | sed 's/:$//')

# Write the daemon loop to a temp script so tmux can source it
LOOP_SCRIPT="$DAEMON_DIR/.daemon_loop.sh"
cat > "$LOOP_SCRIPT" << 'INNEREOF'
#!/bin/bash
INNEREOF

# Append the function and variables
cat >> "$LOOP_SCRIPT" << EOF
PROJECT_ROOT="$PROJECT_ROOT"
DAEMON_DIR="$DAEMON_DIR"
LOG_DIR="$LOG_DIR"
STATE_FILE="$STATE_FILE"
PROMPT_FILE="$PROMPT_FILE"
STOP_FILE="$STOP_FILE"
MODEL="$MODEL"
AGENT="$AGENT"
COOLDOWN=$COOLDOWN
MAX_ITERATIONS=$MAX_ITERATIONS
ITERATION=0
EOF

# Append the function body
declare -f daemon_loop >> "$LOOP_SCRIPT"
echo "daemon_loop" >> "$LOOP_SCRIPT"
chmod +x "$LOOP_SCRIPT"

tmux new-session -d -s "$SESSION_NAME" -c "$PROJECT_ROOT" \
  -e "AWS_PROFILE=ziya" \
  -e "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}" \
  -e "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}" \
  -e "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN:-}" \
  "unset VISUAL; unset EDITOR; export PATH=\"$CLEAN_PATH\"; bash \"$LOOP_SCRIPT\""

echo "═══════════════════════════════════════════════════"
echo "  AEGIS DAEMON v3 — opencode-powered"
echo "  Model: $MODEL"
echo "  Agent: $AGENT"
echo "  Project: $PROJECT_ROOT"
echo "  Prompt: $PROMPT_FILE ($(wc -l < "$PROMPT_FILE") lines)"
echo "  State: $STATE_FILE"
echo "  tmux: $SESSION_NAME"
echo "═══════════════════════════════════════════════════"
echo ""
echo "┌─────────────────────────────────────────────────────────────┐"
echo "│  Attach:    tmux attach -t $SESSION_NAME                    │"
echo "│  Detach:    Ctrl+B then D (keeps running)                   │"
echo "│  Stop:      touch .claude/daemon/STOP                       │"
echo "│  Kill:      tmux kill-session -t $SESSION_NAME              │"
echo "│  State:     cat .claude/daemon/STATE.md                     │"
echo "│  Logs:      ls -la .claude/daemon/logs/                     │"
echo "└─────────────────────────────────────────────────────────────┘"
echo ""
echo "Go to sleep. It's working."
