#!/usr/bin/env bash
set -euo pipefail

# Enhanced QVS-CBOM Demo Script for Customer Presentations
# Features: Better output formatting, CSV generation, summary statistics

# Color codes for better visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
IMAGE=${ENHANCED_SCANNER_IMAGE:-enhanced-scanner}
DOCKER_SOCK=${DOCKER_SOCK_PATH:-/var/run/docker.sock}
KUBECONFIG_DIR=${KUBECONFIG_DIR:-$HOME/.kube}
NAMESPACE=${CBOM_NAMESPACE:-cbom}
TARGET_IMAGE=${CBOM_TARGET_IMAGE:-bkimminich/juice-shop:latest}
OUTPUT_DIR=${OUTPUT_DIR:-./demo-outputs}

# Create output directory
mkdir -p "$OUTPUT_DIR"

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║            QVS-CBOM Quantum Vulnerability Scanner         ║"
    echo "║        Cryptographic Bill of Materials Generator          ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${BLUE}${BOLD}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}═══════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

usage() {
    print_banner
    cat <<USAGE
${BOLD}Usage:${NC} $0 <command> [options]

${BOLD}Commands:${NC}
  juice       Scan OWASP Juice Shop (known quantum vulnerabilities)
  image       Scan any container image
  k8s         Scan Kubernetes namespace
  filesystem  Scan local filesystem
  all         Run all demo scenarios

${BOLD}Options:${NC}
  --csv       Generate CSV report (default: enabled)
  --json      Save JSON CBOM output (default: enabled)
  --summary   Show vulnerability summary (default: enabled)
  --verbose   Show detailed output

${BOLD}Examples:${NC}
  $0 juice                    # Quick Juice Shop demo
  $0 image nginx:latest       # Scan specific image
  $0 k8s --namespace default  # Scan K8s namespace
  $0 filesystem /path/to/app  # Scan local directory

${BOLD}Environment Variables:${NC}
  ENHANCED_SCANNER_IMAGE  Scanner image (default: enhanced-scanner)
  DOCKER_SOCK_PATH        Docker socket path (default: /var/run/docker.sock)
  CBOM_NAMESPACE          K8s namespace (default: cbom)
  OUTPUT_DIR              Output directory (default: ./demo-outputs)
USAGE
}

check_prerequisites() {
    print_section "Checking Prerequisites"

    # Check Docker
    if command -v docker &> /dev/null; then
        print_success "Docker is installed"
    else
        print_error "Docker is not installed"
        exit 1
    fi

    # Check Docker socket
    if [ -S "$DOCKER_SOCK" ]; then
        print_success "Docker socket found at $DOCKER_SOCK"
    else
        print_error "Docker socket not found at $DOCKER_SOCK"
        exit 1
    fi

    # Check if enhanced scanner image exists
    if docker image inspect "$IMAGE" &> /dev/null; then
        print_success "Enhanced scanner image found: $IMAGE"
    else
        print_warning "Enhanced scanner image not found. Building..."
        if docker build -t "$IMAGE" .; then
            print_success "Successfully built $IMAGE"
        else
            print_error "Failed to build enhanced scanner image"
            exit 1
        fi
    fi

    # Check for QVS-CBOM binary (for local processing)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        CBOM_BINARY="./qvs-cbom-darwin"
    else
        CBOM_BINARY="./qvs-cbom"
    fi

    if [ -x "$CBOM_BINARY" ]; then
        print_success "QVS-CBOM binary found: $CBOM_BINARY"
    else
        print_warning "QVS-CBOM binary not executable, some features may be limited"
    fi
}

extract_cbom_from_output() {
    local log_file="$1"
    # Extract JSON CBOM from the combined output
    sed -n '/^{/,/^}/p' "$log_file" | grep -v "^Running /qvs-cbom"
}

generate_summary() {
    local json_file="$1"

    if [ ! -f "$json_file" ]; then
        return
    fi

    print_section "Quantum Vulnerability Summary"

    # Parse the JSON and create summary
    local total=$(jq '.findings | length' "$json_file" 2>/dev/null || echo "0")
    local critical=$(jq '[.findings[] | select((.risk | ascii_upcase) == "CRITICAL")] | length' "$json_file" 2>/dev/null || echo "0")
    local high=$(jq '[.findings[] | select((.risk | ascii_upcase) == "HIGH")] | length' "$json_file" 2>/dev/null || echo "0")
    local medium=$(jq '[.findings[] | select((.risk | ascii_upcase) == "MEDIUM")] | length' "$json_file" 2>/dev/null || echo "0")
    local low=$(jq '[.findings[] | select((.risk | ascii_upcase) == "LOW")] | length' "$json_file" 2>/dev/null || echo "0")

    echo -e "${BOLD}Total Quantum-Risk Findings:${NC} $total"
    echo ""
    [ "$critical" -gt 0 ] && echo -e "  ${RED}● CRITICAL:${NC} $critical"
    [ "$high" -gt 0 ] && echo -e "  ${YELLOW}● HIGH:${NC}     $high"
    [ "$medium" -gt 0 ] && echo -e "  ${BLUE}● MEDIUM:${NC}   $medium"
    [ "$low" -gt 0 ] && echo -e "  ${GREEN}● LOW:${NC}      $low"

    # Show top vulnerable algorithms
    echo -e "\n${BOLD}Top Vulnerable Algorithms:${NC}"
    jq -r '.findings[] | .algorithm' "$json_file" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -5 | \
        while read count algo; do
            echo "  • $algo ($count occurrences)"
        done

    # Show affected file types
    echo -e "\n${BOLD}Affected File Types:${NC}"
    jq -r '.findings[] | .file' "$json_file" 2>/dev/null | \
        sed 's/.*\.//' | sort | uniq -c | sort -rn | head -5 | \
        while read count ext; do
            echo "  • .$ext ($count files)"
        done
}

run_juice_demo() {
    print_banner
    print_section "OWASP Juice Shop Demo"

    print_info "Target: $TARGET_IMAGE"
    print_info "Known vulnerabilities: MD5, SHA1, weak RSA keys"
    echo ""

    local timestamp=$(date +%Y%m%d_%H%M%S)
    local log_file="$OUTPUT_DIR/juice-shop-$timestamp.log"
    local json_file="$OUTPUT_DIR/juice-shop-$timestamp.json"
    local csv_file="$OUTPUT_DIR/juice-shop-$timestamp.csv"

    print_info "Running combined Trivy + QVS-CBOM scan..."

    # Run the scan and write CBOM JSON directly to a mounted file
    docker run --rm \
        -v "$DOCKER_SOCK":"$DOCKER_SOCK" \
        -e DOCKER_HOST="${DOCKER_HOST:-}" \
        -v "$OUTPUT_DIR":/out \
        -e CBOM_OUTPUT_FILE="/out/juice-shop-$timestamp.json" \
        "$IMAGE" --CBOM image "$TARGET_IMAGE" 2>&1 | tee "$log_file"

    # Confirm JSON saved
    if [ -s "$json_file" ]; then
        print_success "CBOM JSON saved to: $json_file"

        if [ -x "./json-to-csv.sh" ]; then
            print_info "Generating CSV report..."
            ./json-to-csv.sh "$json_file" "$csv_file"
            print_success "CSV report saved to: $csv_file"
        else
            print_warning "json-to-csv.sh not found; skipping CSV generation"
        fi

        # Generate summary
        generate_summary "$json_file"
    else
        print_warning "No CBOM data saved (expected at $json_file)"
    fi

    echo ""
    print_success "Demo complete! Outputs saved to $OUTPUT_DIR/"
}

run_image_demo() {
    local target="${1:-nginx:latest}"
    print_banner
    print_section "Container Image Scan"

    print_info "Target: $target"
    echo ""

    local timestamp=$(date +%Y%m%d_%H%M%S)
    local safe_name=$(echo "$target" | sed 's/[:/]/-/g')
    local log_file="$OUTPUT_DIR/${safe_name}-$timestamp.log"
    local json_file="$OUTPUT_DIR/${safe_name}-$timestamp.json"
    local csv_file="$OUTPUT_DIR/${safe_name}-$timestamp.csv"

    print_info "Running combined Trivy + QVS-CBOM scan..."

    docker run --rm \
        -v "$DOCKER_SOCK":"$DOCKER_SOCK" \
        -e DOCKER_HOST="${DOCKER_HOST:-}" \
        -v "$OUTPUT_DIR":/out \
        -e CBOM_OUTPUT_FILE="/out/${safe_name}-$timestamp.json" \
        "$IMAGE" --CBOM image "$target" 2>&1 | tee "$log_file"

    if [ -s "$json_file" ]; then
        print_success "CBOM JSON saved to: $json_file"

        if [ -x "./json-to-csv.sh" ]; then
            ./json-to-csv.sh "$json_file" "$csv_file"
            print_success "CSV report saved to: $csv_file"
        else
            print_warning "json-to-csv.sh not found; skipping CSV generation"
        fi

        generate_summary "$json_file"
    fi

    echo ""
    print_success "Scan complete! Outputs saved to $OUTPUT_DIR/"
}

run_k8s_demo() {
    print_banner
    print_section "Kubernetes Namespace Scan"

    if [ ! -d "$KUBECONFIG_DIR" ]; then
        print_error "Kubeconfig directory not found: $KUBECONFIG_DIR"
        exit 1
    fi

    print_info "Namespace: $NAMESPACE"
    echo ""

    local timestamp=$(date +%Y%m%d_%H%M%S)
    local log_file="$OUTPUT_DIR/k8s-${NAMESPACE}-$timestamp.log"
    local json_file="$OUTPUT_DIR/k8s-${NAMESPACE}-$timestamp.json"
    local csv_file="$OUTPUT_DIR/k8s-${NAMESPACE}-$timestamp.csv"

    print_info "Running Kubernetes scan..."

    docker run --rm \
        -v "$DOCKER_SOCK":"$DOCKER_SOCK" \
        -v "$KUBECONFIG_DIR":/root/.kube \
        -e DOCKER_HOST="${DOCKER_HOST:-}" \
        -v "$OUTPUT_DIR":/out \
        -e CBOM_OUTPUT_FILE="/out/k8s-${NAMESPACE}-$timestamp.json" \
        "$IMAGE" --CBOM kubernetes --namespace "$NAMESPACE" 2>&1 | tee "$log_file"

    if [ -s "$json_file" ]; then
        print_success "CBOM JSON saved to: $json_file"

        if [ -x "./json-to-csv.sh" ]; then
            ./json-to-csv.sh "$json_file" "$csv_file"
            print_success "CSV report saved to: $csv_file"
        else
            print_warning "json-to-csv.sh not found; skipping CSV generation"
        fi

        generate_summary "$json_file"
    fi

    echo ""
    print_success "K8s scan complete! Outputs saved to $OUTPUT_DIR/"
}

run_filesystem_demo() {
    local target="${1:-.}"
    print_banner
    print_section "Filesystem Scan"

    print_info "Target: $target"
    echo ""

    if [ ! -d "$target" ] && [ ! -f "$target" ]; then
        print_error "Target not found: $target"
        exit 1
    fi

    local timestamp=$(date +%Y%m%d_%H%M%S)
    local safe_name=$(basename "$target")
    local log_file="$OUTPUT_DIR/fs-${safe_name}-$timestamp.log"
    local json_file="$OUTPUT_DIR/fs-${safe_name}-$timestamp.json"
    local csv_file="$OUTPUT_DIR/fs-${safe_name}-$timestamp.csv"

    print_info "Running filesystem scan..."

    docker run --rm \
        -v "$target":/workspace \
        -v "$OUTPUT_DIR":/out \
        -e CBOM_OUTPUT_FILE="/out/fs-${safe_name}-$timestamp.json" \
        "$IMAGE" --CBOM filesystem /workspace 2>&1 | tee "$log_file"

    if [ -s "$json_file" ]; then
        print_success "CBOM JSON saved to: $json_file"

        if [ -x "./json-to-csv.sh" ]; then
            ./json-to-csv.sh "$json_file" "$csv_file"
            print_success "CSV report saved to: $csv_file"
        else
            print_warning "json-to-csv.sh not found; skipping CSV generation"
        fi

        generate_summary "$json_file"
    fi

    echo ""
    print_success "Filesystem scan complete! Outputs saved to $OUTPUT_DIR/"
}

run_all_demos() {
    print_banner
    print_section "Running All Demo Scenarios"

    echo "1. OWASP Juice Shop (Known Quantum Vulnerabilities)"
    echo "2. NGINX (Popular Web Server)"
    echo "3. Kubernetes Namespace (if configured)"
    echo ""

    # Run Juice Shop
    print_info "Starting Juice Shop demo..."
    run_juice_demo

    sleep 2

    # Run NGINX
    print_info "Starting NGINX demo..."
    run_image_demo "nginx:latest"

    # Run K8s if kubeconfig exists
    if [ -d "$KUBECONFIG_DIR" ]; then
        sleep 2
        print_info "Starting Kubernetes demo..."
        run_k8s_demo
    else
        print_warning "Skipping Kubernetes demo (no kubeconfig found)"
    fi

    print_section "All Demos Complete"
    print_success "All outputs saved to $OUTPUT_DIR/"
}

# Main execution
case "${1:-}" in
    juice)
        check_prerequisites
        run_juice_demo
        ;;
    image)
        check_prerequisites
        shift
        run_image_demo "$@"
        ;;
    k8s|kubernetes)
        check_prerequisites
        # Parse namespace if provided
        shift
        while [[ $# -gt 0 ]]; do
            case $1 in
                --namespace|-n)
                    NAMESPACE="$2"
                    shift 2
                    ;;
                *)
                    shift
                    ;;
            esac
        done
        run_k8s_demo
        ;;
    filesystem|fs)
        check_prerequisites
        shift
        run_filesystem_demo "$@"
        ;;
    all)
        check_prerequisites
        run_all_demos
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac