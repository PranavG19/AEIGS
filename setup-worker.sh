#!/bin/bash
# Quick helper: creates a worktree, writes TASK.md, adds local .gitignore for worker artifacts
# Usage: setup-worker.sh <id> <branch-name> <task-file-path>
set -uo pipefail
ID="${1:?}"
BRANCH="${2:?}"
TASK_SRC="${3:?}"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
WT="${BASE_DIR}/.workers/w${ID}"

git worktree add "$WT" -b "$BRANCH" main
cp "$TASK_SRC" "${WT}/TASK.md"

cat > "${WT}/.gitignore" << 'EOF'
TASK.md
HEARTBEAT
STOP
.worker_loop.sh
.worker-logs/
EOF

echo "Worker $ID ready at $WT (branch: $BRANCH)"
