#!/bin/bash

# =============================================================================
# FIPS 140-3 CBOM Demo - Ultra-Simple Pipeline Trigger
# =============================================================================
# No git commits needed - just triggers GitHub Actions via workflow_dispatch
#
# Usage:
#   ./run-demo.sh run        # Trigger and watch pipeline
#   ./run-demo.sh pipeline   # Same as 'run'
#   ./run-demo.sh trigger    # Trigger only (no watch)
#   ./run-demo.sh watch      # Watch latest run
#   ./run-demo.sh list       # List recent runs
# =============================================================================

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_header() {
    echo -e "\n${BLUE}${BOLD}========================================${NC}"
    echo -e "${BLUE}${BOLD}$1${NC}"
    echo -e "${BLUE}${BOLD}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

show_usage() {
    cat << EOF
${CYAN}${BOLD}FIPS 140-3 CBOM Demo - Pipeline Trigger${NC}

${BOLD}Usage:${NC}
  ${GREEN}./run-demo.sh run${NC}        Trigger pipeline and watch
  ${GREEN}./run-demo.sh pipeline${NC}   Same as 'run' (alias)
  ${GREEN}./run-demo.sh trigger${NC}    Trigger only (no watch)
  ${GREEN}./run-demo.sh watch${NC}      Watch latest run
  ${GREEN}./run-demo.sh list${NC}       List recent runs

${BOLD}What This Demo Shows:${NC}
  1. 🏗️  Image build (Juice Shop)
  2. 🔍 Aqua Security scan (may fail - strict FIPS policies)
  3. 📊 CBOM generation - detects crypto algorithms
  4. ⚖️  REGO policy - ${RED}6 VIOLATIONS DETECTED${NC}
  5. 🛑 ${BOLD}PIPELINE BLOCKED${NC} - security gate working

${BOLD}Key Demo Points:${NC}
  • ${YELLOW}627/628${NC} assets quantum-vulnerable
  • ${RED}MD5${NC} deprecated algorithm detected
  • Clear "${RED}PIPELINE BLOCKED${NC}" message (lines 60-62)
  • In production: hard stop (demo uses continue-on-error)

${BOLD}Examples:${NC}
  # Quick demo
  ./run-demo.sh run

  # Just trigger, check later
  ./run-demo.sh trigger

  # Watch latest run
  ./run-demo.sh watch

EOF
}

trigger_pipeline() {
    print_header "🚀 Triggering FIPS 140-3 Compliance Pipeline"

    print_info "Triggering workflow via GitHub Actions API..."
    echo ""

    # Trigger the workflow
    gh workflow run "cbom-fips-pipeline-aqua.yml" --ref master

    print_success "Pipeline triggered successfully!"
    echo ""

    sleep 3

    # Get the latest run ID
    print_info "Fetching run ID..."
    LATEST_RUN=$(gh run list --workflow="cbom-fips-pipeline-aqua.yml" --limit 1 --json databaseId,status --jq '.[0] | select(.status == "queued" or .status == "in_progress" or .status == "waiting") | .databaseId')

    if [ -z "$LATEST_RUN" ]; then
        sleep 3
        LATEST_RUN=$(gh run list --workflow="cbom-fips-pipeline-aqua.yml" --limit 1 --json databaseId --jq '.[0].databaseId')
    fi

    echo ""
    print_success "Run ID: $LATEST_RUN"
    echo ""
    echo "View in browser:"
    echo "  ${CYAN}https://github.com/ppscon/CBOM/actions/runs/$LATEST_RUN${NC}"
    echo ""
}

watch_pipeline() {
    # Get the latest run
    LATEST_RUN=$(gh run list --workflow="cbom-fips-pipeline-aqua.yml" --limit 1 --json databaseId --jq '.[0].databaseId')

    if [ -z "$LATEST_RUN" ]; then
        print_warning "No recent pipeline runs found"
        exit 1
    fi

    print_header "👀 Watching Pipeline: $LATEST_RUN"
    gh run watch "$LATEST_RUN" || true
}

list_runs() {
    print_header "📋 Recent Pipeline Runs"
    gh run list --workflow="cbom-fips-pipeline-aqua.yml" --limit 5
}

run_demo() {
    trigger_pipeline

    read -p "Watch this run now? (y/n) " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        LATEST_RUN=$(gh run list --workflow="cbom-fips-pipeline-aqua.yml" --limit 1 --json databaseId --jq '.[0].databaseId')
        gh run watch "$LATEST_RUN" || true
    else
        print_info "Pipeline running in background"
        print_info "Watch later with: ./run-demo.sh watch"
    fi
}

# Main
case "${1:-}" in
    run|pipeline)
        run_demo
        ;;
    trigger)
        trigger_pipeline
        ;;
    watch)
        watch_pipeline
        ;;
    list)
        list_runs
        ;;
    help|--help|-h|"")
        show_usage
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$1'${NC}"
        echo ""
        show_usage
        exit 1
        ;;
esac
