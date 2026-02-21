#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_DIR="$PROJECT_ROOT/defense-stacks/compose"

FIXTURE="${1:-all}"
FAILED=0

validate_fixture() {
    local name="$1"
    local compose_file="$2"
    local ground_truth="$3"
    local port="$4"

    echo "=== Validating $name ==="

    # Start the fixture
    docker compose -f "$compose_file" -p "aegis-validate-$name" up -d --build --wait

    # Wait for health
    local attempts=0
    while ! curl -sf "http://localhost:$port/health" > /dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ $attempts -ge 30 ]; then
            echo "FAIL: $name health check timed out"
            docker compose -f "$compose_file" -p "aegis-validate-$name" down -v 2>/dev/null
            FAILED=$((FAILED + 1))
            return
        fi
        sleep 2
    done

    echo "Health check passed for $name"

    # Verify ground truth file exists and is valid JSON
    if ! jq empty "$ground_truth" 2>/dev/null; then
        echo "FAIL: Invalid ground truth JSON: $ground_truth"
        FAILED=$((FAILED + 1))
    else
        local count
        count=$(jq '.findings | length' "$ground_truth")
        echo "Ground truth has $count expected findings"

        # Verify each endpoint in ground truth is accessible
        jq -r '.findings[] | "\(.method) \(.endpoint)"' "$ground_truth" | while read -r method endpoint; do
            local url="http://localhost:$port$endpoint"
            local status
            if [ "$method" = "POST" ]; then
                status=$(curl -sf -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d '{}' "$url" 2>/dev/null || echo "000")
            else
                status=$(curl -sf -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
            fi
            if [ "$status" = "000" ]; then
                echo "  WARN: $method $endpoint - connection failed"
            else
                echo "  OK: $method $endpoint - HTTP $status"
            fi
        done
    fi

    # Tear down
    docker compose -f "$compose_file" -p "aegis-validate-$name" down -v 2>/dev/null
    echo ""
}

if [ "$FIXTURE" = "all" ] || [ "$FIXTURE" = "express" ]; then
    validate_fixture "express" "$COMPOSE_DIR/docker-compose.yml" \
        "$PROJECT_ROOT/defense-stacks/express-vuln-app/ground-truth.json" 3000
fi

if [ "$FIXTURE" = "all" ] || [ "$FIXTURE" = "flask" ]; then
    validate_fixture "flask" "$COMPOSE_DIR/docker-compose.flask.yml" \
        "$PROJECT_ROOT/defense-stacks/flask-vuln-app/ground-truth.json" 5001
fi

if [ "$FIXTURE" = "all" ] || [ "$FIXTURE" = "graphql" ]; then
    validate_fixture "graphql" "$COMPOSE_DIR/docker-compose.graphql.yml" \
        "$PROJECT_ROOT/defense-stacks/graphql-vuln-app/ground-truth.json" 4000
fi

if [ $FAILED -gt 0 ]; then
    echo "FAILED: $FAILED fixture(s) had errors"
    exit 1
fi

echo "All ground truth validations passed"
