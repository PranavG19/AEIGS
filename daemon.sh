#!/bin/bash
# AEGIS DAEMON v2 | Ralph Loop + tmux
# PROMPT.md = system prompt (all gates/rules/tools, set once, never accumulates)
# Ralph prompt = tiny user message (just "read STATE.md and execute")
#
# Run:     ./daemon.sh
# Monitor: tmux attach -t aegis-daemon
# Stop:    tmux send-keys -t aegis-daemon '/cancel-ralph' Enter
# Kill:    tmux kill-session -t aegis-daemon

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
DAEMON_DIR="$PROJECT_ROOT/.claude/daemon"
LOG_DIR="$DAEMON_DIR/logs"
STATE_FILE="$DAEMON_DIR/STATE.md"
PROMPT_FILE="$DAEMON_DIR/PROMPT.md"
SESSION_NAME="aegis-daemon"

# ── PRE-FLIGHT ──────────────────────────────────────────────────────
mkdir -p "$LOG_DIR" "$DAEMON_DIR"
for cmd in claude git tmux; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "FATAL: $cmd not found"; exit 1; }
done
[ -f "$PROJECT_ROOT/CLAUDE.md" ] || { echo "FATAL: no CLAUDE.md"; exit 1; }
[ -f "$PROMPT_FILE" ]            || { echo "FATAL: no $PROMPT_FILE (system prompt)"; exit 1; }
[ -f "$STATE_FILE" ]             || { echo "FATAL: no $STATE_FILE"; exit 1; }

# ── LOG ROTATION ────────────────────────────────────────────────────
find "$LOG_DIR" -name "*.log" -mtime +2 -delete 2>/dev/null || true

# ── RESOLVE AWS CREDENTIALS ────────────────────────────────────────
# Snapshot live STS tokens from the calling shell into explicit env vars.
# This avoids the tmux child process having to re-resolve an expired profile file.
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
rm -f "$PROJECT_ROOT/.claude/ralph-loop.local.md"
sleep 1

# ── LAUNCH CLAUDE IN TMUX ──────────────────────────────────────────
# Pass explicit credential env vars so the tmux child never re-resolves a stale profile.
# Unset VISUAL/EDITOR to prevent VS Code diff viewer from blocking STATE.md writes.
# Strip VS Code from PATH so Claude doesn't try to open diffs.
CLEAN_PATH=$(echo "$PATH" | tr ':' '\n' | grep -v "Visual Studio Code" | tr '\n' ':' | sed 's/:$//')

tmux new-session -d -s "$SESSION_NAME" -c "$PROJECT_ROOT" \
  -e "AWS_PROFILE=ziya" \
  -e "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}" \
  -e "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}" \
  -e "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN:-}" \
  "unset VISUAL; unset EDITOR; export PATH=\"$CLEAN_PATH\"; claude --dangerously-skip-permissions --model opus --effort high --append-system-prompt-file \"$PROMPT_FILE\" -n daemon-cycle"

echo "═══════════════════════════════════════════════════"
echo "  AEGIS DAEMON v2"
echo "  Project: $PROJECT_ROOT"
echo "  System prompt: $PROMPT_FILE ($(wc -l < "$PROMPT_FILE") lines)"
echo "  State: $STATE_FILE"
echo "  tmux: $SESSION_NAME"
echo "═══════════════════════════════════════════════════"
echo ""
echo "Waiting for Claude to initialize (20s)..."
sleep 20

# ── INJECT RALPH LOOP ──────────────────────────────────────────────
# TINY prompt — all rules live in system prompt (PROMPT.md) already.
# This user message is what Ralph feeds back each iteration. Must stay minimal.
RALPH_CMD='/ralph-loop:ralph-loop Read .claude/daemon/STATE.md and execute the handoff task. After each logical unit: run tests, simplify, commit, update STATE.md. Never stop.'
tmux send-keys -t "$SESSION_NAME" "$RALPH_CMD" Enter

echo "Ralph Loop command sent."
echo ""

# ── VERIFY ACTIVATION ──────────────────────────────────────────────
sleep 8
if [ -f "$PROJECT_ROOT/.claude/ralph-loop.local.md" ]; then
  echo "Ralph Loop ACTIVE."
  grep '^iteration:' "$PROJECT_ROOT/.claude/ralph-loop.local.md" 2>/dev/null
else
  echo "Ralph Loop not detected yet. Retrying..."
  sleep 15
  tmux send-keys -t "$SESSION_NAME" "$RALPH_CMD" Enter
  sleep 8
  if [ -f "$PROJECT_ROOT/.claude/ralph-loop.local.md" ]; then
    echo "Ralph Loop ACTIVE (retry succeeded)."
  else
    echo "WARNING: Ralph Loop state file not found."
    echo "Attach manually: tmux attach -t $SESSION_NAME"
    echo "Then type: $RALPH_CMD"
  fi
fi

echo ""
echo "┌─────────────────────────────────────────────────────────────┐"
echo "│  Attach:    tmux attach -t $SESSION_NAME                    │"
echo "│  Detach:    Ctrl+B then D (keeps running)                   │"
echo "│  Stop:      /cancel-ralph (inside tmux)                     │"
echo "│  Kill:      tmux kill-session -t $SESSION_NAME              │"
echo "│  State:     cat .claude/daemon/STATE.md                     │"
echo "│  Iteration: grep iteration .claude/ralph-loop.local.md      │"
echo "│  Logs:      ls -la .claude/daemon/logs/                     │"
echo "└─────────────────────────────────────────────────────────────┘"
echo ""
echo "System prompt: $(wc -l < "$PROMPT_FILE") lines (set once, never accumulates)"
echo "Ralph prompt: ~30 words (re-sent each iteration, stays tiny)"
echo "Go to sleep. It's working."
