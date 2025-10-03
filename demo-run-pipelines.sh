#!/bin/bash

# =============================================================================
# FIPS 140-3 CBOM Demo Pipeline Runner
# =============================================================================
# Demonstrates both PASS and FAIL scenarios for security compliance gates
#
# Usage:
#   ./demo-run-pipelines.sh compliant    # Run compliant pipeline (PASS)
#   ./demo-run-pipelines.sh violations   # Run violations pipeline (FAIL)
#   ./demo-run-pipelines.sh both         # Run both pipelines
#   ./demo-run-pipelines.sh watch <id>   # Watch a specific run
# =============================================================================

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Pipeline workflow files
COMPLIANT_WORKFLOW="cbom-fips-pipeline-compliant.yml"
VIOLATIONS_WORKFLOW="cbom-fips-pipeline-aqua.yml"

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

run_compliant_pipeline() {
    print_header "🟢 DEMO 1: COMPLIANT IMAGE (All Gates Pass)"

    echo "This pipeline demonstrates:"
    echo "  • Minimal Alpine image with NO cryptographic libraries"
    echo "  • ✅ Aqua scan PASSES (minimal vulnerabilities)"
    echo "  • ✅ CBOM generation PASSES (no crypto found)"
    echo "  • ✅ REGO evaluation PASSES (no violations)"
    echo "  • ✅ Image is PUSHED to registry"
    echo ""

    print_info "Triggering compliant pipeline..."
    RUN_ID=$(gh workflow run "$COMPLIANT_WORKFLOW" --ref master --json 2>&1)

    sleep 3

    LATEST_RUN=$(gh run list --workflow="$COMPLIANT_WORKFLOW" --limit 1 --json databaseId --jq '.[0].databaseId')

    print_success "Pipeline started: Run ID $LATEST_RUN"
    echo ""
    echo "View in browser: https://github.com/ppscon/CBOM/actions/runs/$LATEST_RUN"
    echo ""
    echo "Watch progress:"
    echo "  gh run watch $LATEST_RUN"
    echo ""

    read -p "Watch this run now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        gh run watch "$LATEST_RUN"
    fi
}

run_violations_pipeline() {
    print_header "🔴 DEMO 2: VULNERABLE IMAGE (Crypto Violations Block Push)"

    echo "This pipeline demonstrates:"
    echo "  • Juice Shop image with deprecated cryptography"
    echo "  • ⚠️  Aqua scan FAILS (continue for demo)"
    echo "  • ✅ CBOM generation SUCCEEDS (finds MD5, SHA-3)"
    echo "  • ❌ REGO evaluation FAILS (deprecated algorithms detected)"
    echo "  • 🛑 Image push is BLOCKED"
    echo ""

    print_info "Triggering violations pipeline (via git push)..."

    # Make a trivial change to trigger the pipeline
    echo "# Demo run at $(date)" >> .demo-trigger
    git add .demo-trigger
    git commit -m "demo: trigger FIPS violations pipeline

Demonstrates cryptographic compliance gate blocking vulnerable image.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
    git push

    sleep 3

    LATEST_RUN=$(gh run list --workflow="$VIOLATIONS_WORKFLOW" --limit 1 --json databaseId --jq '.[0].databaseId')

    print_success "Pipeline started: Run ID $LATEST_RUN"
    echo ""
    echo "View in browser: https://github.com/ppscon/CBOM/actions/runs/$LATEST_RUN"
    echo ""
    echo "Watch progress:"
    echo "  gh run watch $LATEST_RUN"
    echo ""

    read -p "Watch this run now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        gh run watch "$LATEST_RUN"
    fi
}

run_both_pipelines() {
    print_header "🎬 FULL DEMO: Both Pipelines (PASS + FAIL)"

    echo "This will run both pipelines in sequence:"
    echo "  1. Compliant pipeline (SUCCESS path)"
    echo "  2. Violations pipeline (BLOCKED path)"
    echo ""

    read -p "Continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi

    run_compliant_pipeline

    echo ""
    print_info "Waiting 10 seconds before starting violations demo..."
    sleep 10

    run_violations_pipeline
}

watch_run() {
    RUN_ID=$1
    if [ -z "$RUN_ID" ]; then
        print_error "Please provide a run ID"
        echo "Usage: $0 watch <run-id>"
        exit 1
    fi

    print_header "Watching Pipeline Run: $RUN_ID"
    gh run watch "$RUN_ID"
}

list_recent_runs() {
    print_header "Recent Pipeline Runs"

    echo -e "${YELLOW}Compliant Pipeline (PASS demo):${NC}"
    gh run list --workflow="$COMPLIANT_WORKFLOW" --limit 3

    echo ""
    echo -e "${YELLOW}Violations Pipeline (FAIL demo):${NC}"
    gh run list --workflow="$VIOLATIONS_WORKFLOW" --limit 3
}

show_usage() {
    cat << EOF
FIPS 140-3 CBOM Demo Pipeline Runner

Usage:
  $0 compliant      Run compliant pipeline (PASS scenario)
  $0 violations     Run violations pipeline (FAIL scenario)
  $0 both           Run both pipelines sequentially
  $0 watch <id>     Watch a specific pipeline run
  $0 list           List recent pipeline runs
  $0 help           Show this help message

Examples:
  # Run compliant demo (all gates pass)
  $0 compliant

  # Run violations demo (REGO blocks push)
  $0 violations

  # Run full demo (both scenarios)
  $0 both

  # Watch a specific run
  $0 watch 12345678

Demo Workflow:
  1. Run 'compliant' to show successful compliance
  2. Run 'violations' to show security gate blocking
  3. Compare results in GitHub Actions UI

EOF
}

# Main script logic
case "$1" in
    compliant)
        run_compliant_pipeline
        ;;
    violations)
        run_violations_pipeline
        ;;
    both)
        run_both_pipelines
        ;;
    watch)
        watch_run "$2"
        ;;
    list)
        list_recent_runs
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        print_error "Invalid command: $1"
        echo ""
        show_usage
        exit 1
        ;;
esac
