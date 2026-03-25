#!/bin/bash
# AEGIS Worker Daemon — runs opencode in a loop inside a git worktree
# Usage: worker-daemon.sh <worker_id> <worktree_path>
#
# Each worker:
# 1. Reads TASK.md from its worktree for the feature assignment
# 2. Runs opencode run in a loop
# 3. Writes HEARTBEAT file with timestamp on each commit
# 4. Commits to its feature branch

set -uo pipefail

WORKER_ID="${1:?Usage: worker-daemon.sh <worker_id> <worktree_path>}"
WORKTREE="${2:?Usage: worker-daemon.sh <worker_id> <worktree_path>}"
SESSION_NAME="aegis-w${WORKER_ID}"
HEARTBEAT_FILE="${WORKTREE}/HEARTBEAT"
TASK_FILE="${WORKTREE}/TASK.md"
LOG_DIR="${WORKTREE}/.worker-logs"
COOLDOWN=10
MODEL="${AEGIS_MODEL:-amazon-bedrock/global.anthropic.claude-opus-4-6-v1}"
AGENT="build"

# ── PRE-FLIGHT ──────────────────────────────────────────────────
mkdir -p "$LOG_DIR"
[ -d "$WORKTREE" ] || { echo "FATAL: worktree $WORKTREE does not exist"; exit 1; }
[ -f "$TASK_FILE" ] || { echo "FATAL: no TASK.md in $WORKTREE"; exit 1; }
command -v opencode >/dev/null 2>&1 || { echo "FATAL: opencode not found"; exit 1; }

# ── PREVENT target/ FROM BEING COMMITTED ────────────────────
cat > "${WORKTREE}/.gitignore" << 'GITEOF'
target/
Cargo.lock
TASK.md
HEARTBEAT
STOP
.worker_loop.sh
.worker-logs/
.DS_Store
GITEOF

# ── RESOLVE AWS CREDENTIALS ────────────────────────────────────
export AWS_PROFILE=ziya
AWS_CREDS=$(aws configure export-credentials --format env 2>/dev/null) || true
if [ -n "$AWS_CREDS" ]; then
  eval "$AWS_CREDS"
fi

# ── KILL PREVIOUS SESSION ──────────────────────────────────────
tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
sleep 1

# ── THE WORKER LOOP ────────────────────────────────────────────
worker_loop() {
  cd "$WORKTREE"
  ITERATION=0

  echo "═══════════════════════════════════════════════════"
  echo "  AEGIS WORKER $WORKER_ID"
  echo "  Worktree: $WORKTREE"
  echo "  Model: $MODEL"
  echo "  Task: $(head -1 TASK.md)"
  echo "═══════════════════════════════════════════════════"

  while true; do
    ITERATION=$((ITERATION + 1))
    TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
    LOG_FILE="$LOG_DIR/iter_${ITERATION}_${TIMESTAMP}.log"

    # ── STOP CHECK ──
    if [ -f "${WORKTREE}/STOP" ]; then
      echo "[$TIMESTAMP] STOP file detected. Worker $WORKER_ID halting."
      rm -f "${WORKTREE}/STOP"
      break
    fi

    echo ""
    echo "━━━ Worker $WORKER_ID | Iteration $ITERATION | $TIMESTAMP ━━━"

    TASK_PROMPT="Read TASK.md. Build the features described in it. Work through the PRIORITY STACK in order.

RULES:
1. Write code IMMEDIATELY. Minimal reading — TASK.md has everything you need.
2. After each logical unit: cargo test -p {crate_name} → git add crates/ hypothesis-engine/ → git commit '[crate] verb phrase'
   CRITICAL: Only git add crates/ and hypothesis-engine/ directories. NEVER git add -A. NEVER commit target/ or Cargo.lock.
3. Write timestamp to HEARTBEAT file with each commit: date > HEARTBEAT
4. Work through ALL tasks in the priority stack. When you finish one task, immediately start the next.
5. If context is filling up, update TASK.md to mark completed tasks and note where you are so the next iteration can continue.
6. After ALL tasks done, mark status as DONE.

BIAS FOR ACTION. Ship code. No analysis paralysis."

    opencode run \
      --dir "$WORKTREE" \
      --model "$MODEL" \
      --agent "$AGENT" \
      "$TASK_PROMPT" \
      2>&1 | tee "$LOG_FILE"

    echo "[$TIMESTAMP] Iteration $ITERATION done (exit=$?)"

    # ── UPDATE HEARTBEAT ──
    date > "$HEARTBEAT_FILE"

    # ── CHECK IF DONE ──
    if grep -q "status: DONE" "$TASK_FILE" 2>/dev/null; then
      echo "[$TIMESTAMP] Worker $WORKER_ID: FEATURE COMPLETE"
      break
    fi

    sleep "$COOLDOWN"
  done

  echo "═══ Worker $WORKER_ID finished ═══"
}

# ── WRITE LOOP SCRIPT ──────────────────────────────────────────
LOOP_SCRIPT="${WORKTREE}/.worker_loop.sh"
cat > "$LOOP_SCRIPT" << EOF
#!/bin/bash
WORKER_ID="$WORKER_ID"
WORKTREE="$WORKTREE"
SESSION_NAME="$SESSION_NAME"
HEARTBEAT_FILE="$HEARTBEAT_FILE"
TASK_FILE="$TASK_FILE"
LOG_DIR="$LOG_DIR"
COOLDOWN=$COOLDOWN
MODEL="$MODEL"
AGENT="$AGENT"
EOF
declare -f worker_loop >> "$LOOP_SCRIPT"
echo "worker_loop" >> "$LOOP_SCRIPT"
chmod +x "$LOOP_SCRIPT"

# ── CLEAN PATH ──────────────────────────────────────────────────
CLEAN_PATH=$(echo "$PATH" | tr ':' '\n' | grep -v "Visual Studio Code" | tr '\n' ':' | sed 's/:$//')

# ── LAUNCH IN TMUX ──────────────────────────────────────────────
tmux new-session -d -s "$SESSION_NAME" -c "$WORKTREE" \
  -e "AWS_PROFILE=ziya" \
  -e "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}" \
  -e "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}" \
  -e "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN:-}" \
  "unset VISUAL; unset EDITOR; export PATH=\"$CLEAN_PATH\"; bash \"$LOOP_SCRIPT\""

echo "Worker $WORKER_ID launched in tmux session: $SESSION_NAME"
echo "  Attach: tmux attach -t $SESSION_NAME"
echo "  Stop:   touch ${WORKTREE}/STOP"
