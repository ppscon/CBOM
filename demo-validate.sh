#!/usr/bin/env bash
set -euo pipefail

# Demo Validation Script - Run before customer presentations
# Ensures all components are ready for a successful demo

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}Aqua-CBOM Demo Validation${NC}\n"

ISSUES=0

check_item() {
    local item="$1"
    local check_cmd="$2"
    local fix_hint="$3"

    printf "Checking %-40s " "$item..."
    if eval "$check_cmd" &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        echo -e "  ${YELLOW}Fix:${NC} $fix_hint"
        ((ISSUES++))
        return 1
    fi
}

echo -e "${BOLD}Prerequisites:${NC}"
check_item "Docker installed" "command -v docker" "Install Docker Desktop or Docker Engine"
check_item "Docker running" "docker info" "Start Docker Desktop/daemon"
check_item "Docker socket" "[ -S /var/run/docker.sock ]" "Ensure Docker is running"

echo -e "\n${BOLD}Binaries:${NC}"
check_item "aqua-cbom (Linux)" "[ -f aqua-cbom ]" "Missing Linux binary"
check_item "aqua-cbom-darwin (macOS)" "[ -f aqua-cbom-darwin ]" "Missing macOS binary"
check_item "aqua-cbom executable" "[ -x aqua-cbom ] || [ -x aqua-cbom-darwin ]" "chmod +x aqua-cbom*"
check_item "wrapper.sh" "[ -x wrapper.sh ]" "chmod +x wrapper.sh"
check_item "aqua-cbom-csv.sh" "[ -x aqua-cbom-csv.sh ]" "chmod +x aqua-cbom-csv.sh"
check_item "json-to-csv.sh" "[ -x json-to-csv.sh ]" "chmod +x json-to-csv.sh"

echo -e "\n${BOLD}Docker Images:${NC}"
check_item "Enhanced scanner built" "docker image inspect enhanced-scanner" "Run: docker build -t enhanced-scanner ."
check_item "Juice Shop available" "docker image inspect bkimminich/juice-shop:latest || docker pull bkimminich/juice-shop:latest" "Will be pulled on first run"

echo -e "\n${BOLD}Demo Scripts:${NC}"
check_item "demo.sh executable" "[ -x demo.sh ]" "chmod +x demo.sh"
check_item "docker-run-csv.sh executable" "[ -x docker-run-csv.sh ]" "chmod +x docker-run-csv.sh"

echo -e "\n${BOLD}Optional Components:${NC}"
check_item "jq installed (for summaries)" "command -v jq" "Install jq for JSON parsing (brew install jq)"
check_item "Python3 (for CSV conversion)" "command -v python3" "Install Python 3"
check_item "Kubeconfig (for K8s demo)" "[ -d ~/.kube ] && [ -f ~/.kube/config ]" "Configure kubectl for K8s demos"

echo -e "\n${BOLD}Output Directory:${NC}"
check_item "demo-outputs directory" "mkdir -p demo-outputs && [ -w demo-outputs ]" "Create writable output directory"

# Quick functionality test
echo -e "\n${BOLD}Quick Functionality Test:${NC}"
if [ -x "./aqua-cbom-darwin" ] || [ -x "./aqua-cbom" ]; then
    printf "Testing Aqua-CBOM binary... "
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if ./aqua-cbom-darwin -version &>/dev/null; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}✗${NC}"
            ((ISSUES++))
        fi
    else
        if ./aqua-cbom -version &>/dev/null; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}✗${NC}"
            ((ISSUES++))
        fi
    fi
fi

# Summary
echo -e "\n${BOLD}═══════════════════════════════════════${NC}"
if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✓ All checks passed! Ready for demo.${NC}"
    echo -e "\n${BOLD}Quick Start:${NC}"
    echo "  ./demo.sh juice     # Run Juice Shop demo"
    echo "  ./demo.sh all        # Run all demos"
    echo "  ./demo.sh --help     # See all options"
else
    echo -e "${RED}${BOLD}✗ Found $ISSUES issue(s). Please fix before demo.${NC}"
    exit 1
fi