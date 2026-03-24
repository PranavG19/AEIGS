#!/bin/bash
PROJECT_ROOT="/Users/pranavgk/Documents/temp/adver"
DAEMON_DIR="/Users/pranavgk/Documents/temp/adver/.claude/daemon"
LOG_DIR="/Users/pranavgk/Documents/temp/adver/.claude/daemon/logs"
STATE_FILE="/Users/pranavgk/Documents/temp/adver/.claude/daemon/STATE.md"
PROMPT_FILE="/Users/pranavgk/Documents/temp/adver/.claude/daemon/PROMPT.md"
STOP_FILE="/Users/pranavgk/Documents/temp/adver/.claude/daemon/STOP"
MODEL="amazon-bedrock/global.anthropic.claude-opus-4-6-v1"
AGENT="build"
COOLDOWN=10
MAX_ITERATIONS=0
ITERATION=0
daemon_loop () 
{ 
    cd "$PROJECT_ROOT";
    echo "═══════════════════════════════════════════════════";
    echo "  AEGIS DAEMON v3 — opencode-powered";
    echo "  Model: $MODEL";
    echo "  Agent: $AGENT";
    echo "  Project: $PROJECT_ROOT";
    echo "═══════════════════════════════════════════════════";
    echo "";
    while true; do
        ITERATION=$((ITERATION + 1));
        TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S);
        LOG_FILE="$LOG_DIR/iteration_${ITERATION}_${TIMESTAMP}.log";
        if [ -f "$STOP_FILE" ]; then
            echo "[$TIMESTAMP] STOP file detected. Daemon halting gracefully.";
            rm -f "$STOP_FILE";
            break;
        fi;
        if [ "$MAX_ITERATIONS" -gt 0 ] && [ "$ITERATION" -gt "$MAX_ITERATIONS" ]; then
            echo "[$TIMESTAMP] Max iterations ($MAX_ITERATIONS) reached. Stopping.";
            break;
        fi;
        echo "";
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
        echo "  ITERATION $ITERATION — $TIMESTAMP";
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
        TASK_PROMPT="Read .claude/daemon/STATE.md and .claude/daemon/PROMPT.md. Then IMMEDIATELY start writing code.

CRITICAL: Do NOT spend more than 2 minutes reading files. You already know the codebase from CLAUDE.md. Read STATE.md for the current task, skim PROMPT.md for gates, then START CODING.

Execute the handoff task in STATE.md. Write code FIRST, explore SECOND.

Per-unit workflow: write code → cargo test -p {crate} → git add + commit '[component] verb' → update STATE.md.

If you finish the current task, move to the next sub-priority in the phase.
If you finish the phase, move to the next phase.
If all phases done, enter INFINITE ROI LOOP (see PROMPT.md).

Before context fills: write a PRECISE handoff in STATE.md (exact file, exact line, exact next action).
BIAS FOR ACTION. Ship code. No analysis paralysis.";
        echo "[$TIMESTAMP] Launching opencode run...";
        opencode run --dir "$PROJECT_ROOT" --model "$MODEL" --agent "$AGENT" "$TASK_PROMPT" 2>&1 | tee "$LOG_FILE";
        EXIT_CODE=$?;
        echo "";
        echo "[$TIMESTAMP] Iteration $ITERATION completed (exit=$EXIT_CODE)";
        if [ -f "$STATE_FILE" ]; then
            echo "[$TIMESTAMP] Current state:";
            head -10 "$STATE_FILE";
        fi;
        echo "[$TIMESTAMP] Cooling down ${COOLDOWN}s...";
        sleep "$COOLDOWN";
    done;
    echo "";
    echo "═══════════════════════════════════════════════════";
    echo "  DAEMON STOPPED — Iteration $ITERATION";
    echo "═══════════════════════════════════════════════════"
}
daemon_loop
