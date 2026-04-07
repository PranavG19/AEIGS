#!/bin/bash

# AEGIS Daemon Control Script
# Simple interface for managing the daemon system

WORK_BASE="/tmp/aegis_daemons"

show_usage() {
    echo "AEGIS Daemon Control System"
    echo "=========================="
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start [target_url]     - Start all daemons (default target: http://127.0.0.1:8080)"
    echo "  stop                   - Stop all daemons"
    echo "  status                 - Show daemon status"
    echo "  monitor                - Monitor daemon activity"
    echo "  logs [daemon]          - Show logs for a daemon"
    echo "  list                   - List all daemons"
    echo "  stats                  - Show daemon statistics"
    echo ""
    echo "Examples:"
    echo "  $0 start https://target.example.com"
    echo "  $0 logs ghost-protocol"
    echo "  $0 monitor"
}

start_daemons() {
    local target_url="${1:-http://127.0.0.1:8080}"
    echo "🚀 Starting AEGIS Daemon System..."
    ./launch_daemons.sh "$target_url"
}

stop_daemons() {
    echo "🛑 Stopping all daemons..."
    if pkill -f daemon_runner.sh; then
        echo "✅ All daemons stopped"
        # Clean up PID files
        rm -f "$WORK_BASE"/*/daemon.pid 2>/dev/null
    else
        echo "⚠️  No daemons found to stop"
    fi
}

show_status() {
    echo "📊 AEGIS Daemon Status"
    echo "====================="
    for daemon in ghost-protocol cache-poisoning schema-grammar http2-flood; do
        if [ -d "$WORK_BASE/$daemon" ]; then
            echo ""
            echo "🔷 $daemon"
            if [ -f "$WORK_BASE/$daemon/daemon.pid" ]; then
                local pid=$(cat "$WORK_BASE/$daemon/daemon.pid")
                if kill -0 $pid 2>/dev/null; then
                    echo "  Status: ✅ RUNNING (PID: $pid)"
                    # Show uptime
                    local uptime=$(ps -o etime= -p $pid 2>/dev/null | xargs echo || echo "N/A")
                    echo "  Uptime: $uptime"
                    
                    # Show metrics
                    local tasks=0
                    local artifacts=0
                    if [ -f "$WORK_BASE/$daemon/logs/progress.log" ]; then
                        tasks=$(wc -l < "$WORK_BASE/$daemon/logs/progress.log" 2>/dev/null || echo "0")
                    fi
                    if [ -d "$WORK_BASE/$daemon/workspace/artifacts" ]; then
                        artifacts=$(ls "$WORK_BASE/$daemon/workspace/artifacts/" 2>/dev/null | wc -l | xargs echo)
                    fi
                    echo "  Tasks: $tasks | Artifacts: $artifacts"
                else
                    echo "  Status: ❌ STOPPED"
                fi
            else
                echo "  Status: ❓ NOT RUNNING"
            fi
        fi
    done
}

show_logs() {
    local daemon="$1"
    if [ -z "$daemon" ]; then
        echo "❌ Please specify a daemon name"
        echo "Available daemons: ghost-protocol cache-poisoning schema-grammar http2-flood"
        return 1
    fi
    
    if [ ! -d "$WORK_BASE/$daemon" ]; then
        echo "❌ Daemon '$daemon' not found"
        return 1
    fi
    
    echo "📋 Logs for $daemon daemon:"
    echo "=========================="
    if [ -f "$WORK_BASE/$daemon/logs/progress.log" ]; then
        echo ""
        echo "Progress Log:"
        tail -10 "$WORK_BASE/$daemon/logs/progress.log" 2>/dev/null || echo "No progress log"
    fi
    
    if [ -f "$WORK_BASE/$daemon/logs/heartbeat.log" ]; then
        echo ""
        echo "Heartbeat Log:"
        tail -5 "$WORK_BASE/$daemon/logs/heartbeat.log" 2>/dev/null || echo "No heartbeat log"
    fi
}

list_daemons() {
    echo "📋 AEGIS Daemons:"
    echo "================="
    for daemon in ghost-protocol cache-poisoning schema-grammar http2-flood; do
        if [ -d "$WORK_BASE/$daemon" ]; then
            echo "🔷 $daemon"
        fi
    done
}

show_stats() {
    echo "📈 AEGIS Daemon Statistics"
    echo "========================="
    local total_tasks=0
    local total_artifacts=0
    local running_daemons=0
    
    for daemon in ghost-protocol cache-poisoning schema-grammar http2-flood; do
        if [ -d "$WORK_BASE/$daemon" ]; then
            local tasks=0
            local artifacts=0
            
            if [ -f "$WORK_BASE/$daemon/logs/progress.log" ]; then
                tasks=$(wc -l < "$WORK_BASE/$daemon/logs/progress.log" 2>/dev/null || echo "0")
            fi
            
            if [ -d "$WORK_BASE/$daemon/workspace/artifacts" ]; then
                artifacts=$(ls "$WORK_BASE/$daemon/workspace/artifacts/" 2>/dev/null | wc -l | xargs echo)
            fi
            
            echo "🔷 $daemon: $tasks tasks, $artifacts artifacts"
            total_tasks=$((total_tasks + tasks))
            total_artifacts=$((total_artifacts + artifacts))
            
            if [ -f "$WORK_BASE/$daemon/daemon.pid" ]; then
                local pid=$(cat "$WORK_BASE/$daemon/daemon.pid")
                if kill -0 $pid 2>/dev/null; then
                    running_daemons=$((running_daemons + 1))
                fi
            fi
        fi
    done
    
    echo ""
    echo "📊 Summary:"
    echo "  Total Tasks: $total_tasks"
    echo "  Total Artifacts: $total_artifacts"
    echo "  Running Daemons: $running_daemons/4"
}

# Main command router
case "${1:-help}" in
    start)
        start_daemons "$2"
        ;;
    stop)
        stop_daemons
        ;;
    status)
        show_status
        ;;
    monitor)
        if [ -f "./monitor_daemons.sh" ]; then
            ./monitor_daemons.sh
        else
            echo "❌ Monitor script not found"
        fi
        ;;
    logs)
        show_logs "$2"
        ;;
    list)
        list_daemons
        ;;
    stats)
        show_stats
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        echo "❌ Unknown command: $1"
        show_usage
        exit 1
        ;;
esac