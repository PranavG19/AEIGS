#!/bin/bash

# AEGIS Daemon Monitoring Script
# Continuously monitors daemon health, logs, and progress

WORK_BASE="/tmp/aegis_daemons"

echo "🔍 AEGIS Daemon Monitoring System"
echo "================================="
echo "📂 Monitoring worktrees at: $WORK_BASE"
echo ""

# Function to get daemon status
get_daemon_status() {
    local daemon="$1"
    local work_dir="$WORK_BASE/$daemon"
    
    if [ -f "$work_dir/daemon.pid" ]; then
        local pid=$(cat "$work_dir/daemon.pid")
        if kill -0 $pid 2>/dev/null; then
            echo "✅ RUNNING (PID: $pid)"
            return 0
        else
            echo "❌ STOPPED (PID: $pid)"
            return 1
        fi
    else
        echo "❓ NOT FOUND"
        return 2
    fi
}

# Function to get daemon metrics
get_daemon_metrics() {
    local daemon="$1"
    local work_dir="$WORK_BASE/$daemon"
    
    local task_count=0
    local artifact_count=0
    local uptime="N/A"
    
    if [ -f "$work_dir/logs/progress.log" ]; then
        task_count=$(wc -l < "$work_dir/logs/progress.log" 2>/dev/null || echo "0")
    fi
    
    if [ -d "$work_dir/workspace/artifacts" ]; then
        artifact_count=$(ls "$work_dir/workspace/artifacts/" 2>/dev/null | wc -l | xargs echo)
    fi
    
    if [ -f "$work_dir/daemon.pid" ]; then
        local pid=$(cat "$work_dir/daemon.pid")
        if kill -0 $pid 2>/dev/null; then
            # Get process uptime
            uptime=$(ps -o etime= -p $pid 2>/dev/null | xargs echo || echo "N/A")
        fi
    fi
    
    echo "Tasks: $task_count | Artifacts: $artifact_count | Uptime: $uptime"
}

# Function to show recent activity
show_recent_activity() {
    local daemon="$1"
    local work_dir="$WORK_BASE/$daemon"
    
    if [ -f "$work_dir/logs/progress.log" ]; then
        echo "Recent:"
        tail -2 "$work_dir/logs/progress.log" 2>/dev/null | sed 's/^/  /' || echo "  No activity"
    else
        echo "Recent: No activity log"
    fi
}

# Main monitoring loop
echo "📊 Daemon Status Dashboard"
echo "=========================="

while true; do
    echo ""
    echo "🕐 Last Updated: $(date)"
    echo "--------------------"
    
    for daemon in ghost-protocol cache-poisoning schema-grammar http2-flood; do
        echo ""
        echo "🔷 $daemon"
        echo "  Status: $(get_daemon_status $daemon)"
        echo "  Metrics: $(get_daemon_metrics $daemon)"
        show_recent_activity $daemon
    done
    
    echo ""
    echo "📈 Summary:"
    echo "  Total Daemons: 4"
    local running_count=0
    for daemon in ghost-protocol cache-poisoning schema-grammar http2-flood; do
        if [ -f "$WORK_BASE/$daemon/daemon.pid" ]; then
            local pid=$(cat "$WORK_BASE/$daemon/daemon.pid")
            if kill -0 $pid 2>/dev/null; then
                running_count=$((running_count + 1))
            fi
        fi
    done
    echo "  Running: $running_count/4"
    
    echo ""
    echo "🔄 Refreshing in 30 seconds... (Ctrl+C to exit)"
    sleep 30
done