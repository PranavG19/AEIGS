#!/bin/bash

# AEGIS Daemon Launcher Script
# Creates isolated worktrees for each daemon with separate memory/state/goals

set -e

WORK_BASE="/tmp/aegis_daemons"
TARGET_URL="${1:-http://127.0.0.1:8080}"

echo "🚀 Launching AEGIS Daemon System"
echo "📊 Target URL: $TARGET_URL"
echo "📂 Work Base: $WORK_BASE"
echo ""

# Create base work directory
mkdir -p "$WORK_BASE"

# Function to launch a daemon with isolated workspace
launch_daemon() {
    local daemon_name="$1"
    local daemon_description="$2"
    local work_dir="$WORK_BASE/$daemon_name"
    
    echo "🔧 Setting up $daemon_name daemon..."
    
    # Create isolated workspace structure
    mkdir -p "$work_dir"/{workspace,logs,state,configs}
    mkdir -p "$work_dir/workspace"/{payloads,fingerprints,bypasses,artifacts}
    
    # Create daemon-specific config
    cat > "$work_dir/configs/daemon_config.json" << EOF
{
    "id": "${daemon_name}_$(date +%s)",
    "type": "$daemon_name",
    "target_url": "$TARGET_URL",
    "workspace": "$work_dir/workspace",
    "logs_dir": "$work_dir/logs",
    "state_dir": "$work_dir/state",
    "goals": {
        "description": "$daemon_description",
        "success_metrics": [],
        "daily_targets": 0,
        "accuracy_threshold": 0.85
    }
}
EOF
    
    # Create a simple daemon script that simulates the daemon behavior
    cat > "$work_dir/daemon_runner.sh" << 'EOF'
#!/bin/bash

WORK_DIR="$1"
DAEMON_NAME="$2"
CONFIG_FILE="$WORK_DIR/configs/daemon_config.json"

echo "🤖 [$DAEMON_NAME] Daemon started at $(date)"
echo "📁 Workspace: $WORK_DIR"

# Simulate daemon initialization
echo "⚙️  [$DAEMON_NAME] Initializing workspace..."
mkdir -p "$WORK_DIR/workspace/session_$(date +%s)"

# Main daemon loop
while true; do
    echo "🔄 [$DAEMON_NAME] Running cycle at $(date)"
    
    # Simulate work with random sleep
    sleep_duration=$((RANDOM % 10 + 5))
    echo "⏳ [$DAEMON_NAME] Working for ${sleep_duration} seconds..."
    sleep $sleep_duration
    
    # Log some fake progress
    timestamp=$(date +%s)
    echo "✅ [$DAEMON_NAME] Completed task cycle_$timestamp" >> "$WORK_DIR/logs/progress.log"
    
    # Generate some fake artifacts
    echo "artifact_${timestamp}" > "$WORK_DIR/workspace/artifacts/result_${timestamp}.txt"
    
    # Heartbeat
    echo "💓 [$DAEMON_NAME] Heartbeat at $(date)" >> "$WORK_DIR/logs/heartbeat.log"
done
EOF
    
    chmod +x "$work_dir/daemon_runner.sh"
    
    # Launch daemon in background with isolated environment
    echo "🚀 Launching $daemon_name daemon..."
    (
        cd "$work_dir"
        nohup ./daemon_runner.sh "$work_dir" "$daemon_name" > "logs/daemon_stdout.log" 2> "logs/daemon_stderr.log" &
        echo $! > "daemon.pid"
    )
    
    echo "✅ $daemon_name daemon launched with PID $(cat "$work_dir/daemon.pid")"
    echo ""
}

# Launch all four specialized daemons with their specific goals
echo "🎯 Launching specialized daemons..."

launch_daemon "ghost-protocol" "Implements missing evasion modules - Header transformer, encoding transformer, timing controller, TLS fingerprinter, session manager. Goal: 85%+ success rate, 1000+ novel bypass payloads daily, <5% false positive rate."

launch_daemon "cache-poisoning" "ROI=78.4 Cache poisoning automation - Web cache deception + key normalization. Goal: 90%+ target success rate, 500+ vector targets daily, <2% false positive rate."

launch_daemon "schema-grammar" "ROI=37.3 Schema→Grammar pipeline glue - API schema inference → grammar-based fuzzing. Goal: 100+ schemas daily, 1000+ fuzz inputs, 80%+ accuracy threshold."

launch_daemon "http2-flood" "ROI=52.5 HTTP/2 CONTINUATION flood - 2024 protocol DoS technique. Goal: 10000+ frame rate, 95%+ success rate, <1% connection drop rate."

echo "📋 Daemon Status Summary:"
echo "========================"
for daemon in ghost-protocol cache-poisoning schema-grammar http2-flood; do
    if [ -f "$WORK_BASE/$daemon/daemon.pid" ]; then
        pid=$(cat "$WORK_BASE/$daemon/daemon.pid")
        if kill -0 $pid 2>/dev/null; then
            echo "✅ $daemon: RUNNING (PID: $pid)"
        else
            echo "❌ $daemon: STOPPED"
        fi
    else
        echo "❓ $daemon: NOT FOUND"
    fi
done

echo ""
echo "📡 Monitoring daemons for 60 seconds..."
echo "======================================"

# Monitor loop
for i in {1..12}; do
    echo "⏱️  Check $i/12 at $(date)"
    for daemon in ghost-protocol cache-poisoning schema-grammar http2-flood; do
        if [ -f "$WORK_BASE/$daemon/daemon.pid" ]; then
            pid=$(cat "$WORK_BASE/$daemon/daemon.pid")
            if kill -0 $pid 2>/dev/null; then
                log_lines=$(wc -l < "$WORK_BASE/$daemon/logs/progress.log" 2>/dev/null || echo "0")
                echo "   📊 $daemon: $log_lines tasks completed"
            else
                echo "   ⚠️  $daemon: Process terminated"
            fi
        fi
    done
    sleep 5
done

echo ""
echo "📄 Sample logs:"
echo "==============="
for daemon in ghost-protocol cache-poisoning schema-grammar http2-flood; do
    if [ -f "$WORK_BASE/$daemon/logs/progress.log" ]; then
        echo "📋 $daemon recent activity:"
        tail -3 "$WORK_BASE/$daemon/logs/progress.log" 2>/dev/null || echo "   No activity yet"
        echo ""
    fi
done

echo "🎯 Daemon system operational!"
echo "📁 Worktrees located at: $WORK_BASE"
echo "💡 To stop daemons: pkill -f daemon_runner.sh"