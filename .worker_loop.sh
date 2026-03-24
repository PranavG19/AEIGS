#!/bin/bash
WORKER_ID="2"
WORKTREE="/Users/pranavgk/Documents/temp/adver/.workers/w2"
SESSION_NAME="aegis-w2"
HEARTBEAT_FILE="/Users/pranavgk/Documents/temp/adver/.workers/w2/HEARTBEAT"
TASK_FILE="/Users/pranavgk/Documents/temp/adver/.workers/w2/TASK.md"
LOG_DIR="/Users/pranavgk/Documents/temp/adver/.workers/w2/.worker-logs"
COOLDOWN=10
MODEL="amazon-bedrock/global.anthropic.claude-opus-4-6-v1"
AGENT="build"
worker_loop () 
{ 
    cd "$WORKTREE";
    ITERATION=0;
    echo "═══════════════════════════════════════════════════";
    echo "  AEGIS WORKER $WORKER_ID";
    echo "  Worktree: $WORKTREE";
    echo "  Model: $MODEL";
    echo "  Task: $(head -1 TASK.md)";
    echo "═══════════════════════════════════════════════════";
    while true; do
        ITERATION=$((ITERATION + 1));
        TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S);
        LOG_FILE="$LOG_DIR/iter_${ITERATION}_${TIMESTAMP}.log";
        if [ -f "${WORKTREE}/STOP" ]; then
            echo "[$TIMESTAMP] STOP file detected. Worker $WORKER_ID halting.";
            rm -f "${WORKTREE}/STOP";
            break;
        fi;
        echo "";
        echo "━━━ Worker $WORKER_ID | Iteration $ITERATION | $TIMESTAMP ━━━";
        TASK_PROMPT="Read TASK.md. Build the feature described in it. This is your ONLY job.

RULES:
1. Write code IMMEDIATELY. Minimal reading — TASK.md has everything you need.
2. After each logical unit: cargo test -p {crate_name} → git add -A → git commit '[crate] verb phrase' 
3. Write timestamp to HEARTBEAT file with each commit: date > HEARTBEAT
4. When the feature is COMPLETE (all acceptance criteria met): write DONE to TASK.md status field.
5. After marking DONE, run cargo clippy -p {crate_name} -- -D warnings and fix any issues.
6. Then STOP. Do not start new features. Your job is done.

BIAS FOR ACTION. Ship code. No analysis paralysis.";
        opencode run --dir "$WORKTREE" --model "$MODEL" --agent "$AGENT" "$TASK_PROMPT" 2>&1 | tee "$LOG_FILE";
        echo "[$TIMESTAMP] Iteration $ITERATION done (exit=$?)";
        date > "$HEARTBEAT_FILE";
        if grep -q "status: DONE" "$TASK_FILE" 2> /dev/null; then
            echo "[$TIMESTAMP] Worker $WORKER_ID: FEATURE COMPLETE";
            break;
        fi;
        sleep "$COOLDOWN";
    done;
    echo "═══ Worker $WORKER_ID finished ═══"
}
worker_loop
