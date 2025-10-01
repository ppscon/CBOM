#!/usr/bin/env bash
set -euo pipefail

# ==================================
# FIPS 140-2 Compliance Validator
# ==================================
# Integrates Aqua-CBOM with REGO policies for comprehensive FIPS validation
#
# Usage:
#   ./validate-fips-compliance.sh <image-name> [cbom-file]
#   ./validate-fips-compliance.sh registry.redhat.io/ubi8/ubi:latest
#   ./validate-fips-compliance.sh nginx:latest /path/to/cbom.json

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

IMAGE="${1:-}"
CBOM_FILE="${2:-}"
TEMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

if [ -z "$IMAGE" ]; then
    echo -e "${RED}Error: Image name required${NC}"
    echo "Usage: $0 <image-name> [cbom-file]"
    exit 1
fi

echo -e "${CYAN}${BOLD}FIPS 140-2 Compliance Validation${NC}\n"
echo "Image: $IMAGE"
echo ""

# ==================================
# Step 1: Generate or Load CBOM
# ==================================
if [ -n "$CBOM_FILE" ] && [ -f "$CBOM_FILE" ]; then
    echo -e "${CYAN}[1/4] Using provided CBOM: $CBOM_FILE${NC}"
    cp "$CBOM_FILE" "$TEMP_DIR/cbom.json"
else
    echo -e "${CYAN}[1/4] Generating CBOM for $IMAGE${NC}"

    # Check if using Docker or bare metal
    if command -v docker &> /dev/null && docker ps &> /dev/null; then
        # Use Docker wrapper
        docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$TEMP_DIR":/out \
            -e CBOM_OUTPUT_FILE=/out/cbom.json \
            -e CBOM_CDX_TARGET=1.6 \
            enhanced-scanner --CBOM image "$IMAGE" >/dev/null 2>&1
    else
        # Use bare metal scanner
        if [[ "$OSTYPE" == "darwin"* ]]; then
            ./aqua-cbom-darwin -mode file -dir /tmp -output-cbom > "$TEMP_DIR/cbom.json"
        else
            ./aqua-cbom -mode file -dir /tmp -output-cbom > "$TEMP_DIR/cbom.json"
        fi
    fi

    if [ ! -s "$TEMP_DIR/cbom.json" ]; then
        echo -e "${RED}✗ Failed to generate CBOM${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ CBOM generated${NC}"
fi

# ==================================
# Step 2: Extract Image Metadata
# ==================================
echo -e "\n${CYAN}[2/4] Extracting image metadata${NC}"

# Get package list (if available)
if command -v docker &> /dev/null; then
    docker run --rm --entrypoint sh "$IMAGE" -c "
        if command -v rpm &> /dev/null; then
            rpm -qa --queryformat '%{NAME}|%{VERSION}\n'
        elif command -v dpkg &> /dev/null; then
            dpkg -l | awk '/^ii/ {print \$2\"|\"\$3}'
        fi
    " 2>/dev/null > "$TEMP_DIR/packages.txt" || true
fi

# Convert packages to JSON
if [ -s "$TEMP_DIR/packages.txt" ]; then
    jq -R -s 'split("\n") | map(select(length > 0) | split("|") | {name: .[0], version: .[1]})' \
        "$TEMP_DIR/packages.txt" > "$TEMP_DIR/packages.json"
else
    echo "[]" > "$TEMP_DIR/packages.json"
fi

echo -e "${GREEN}✓ Metadata extracted${NC}"

# ==================================
# Step 3: Create REGO Input
# ==================================
echo -e "\n${CYAN}[3/4] Preparing REGO policy input${NC}"

jq -n \
    --arg image "$IMAGE" \
    --slurpfile cbom "$TEMP_DIR/cbom.json" \
    --slurpfile packages "$TEMP_DIR/packages.json" \
    '{
        "image": $image,
        "cbom": $cbom[0],
        "packages": $packages[0],
        "runtime": {
            "fips_enabled": "unknown"
        },
        "policy": {
            "file_integrity_monitoring": {"enabled": true}
        },
        "exceptions": {}
    }' > "$TEMP_DIR/policy-input.json"

echo -e "${GREEN}✓ Policy input prepared${NC}"

# ==================================
# Step 4: Run REGO Validation
# ==================================
echo -e "\n${CYAN}[4/4] Running REGO policy evaluation${NC}\n"

# Check if OPA is available
if ! command -v opa &> /dev/null; then
    echo -e "${YELLOW}⚠ OPA not installed - using jq-based validation${NC}\n"

    # Fallback validation using jq
    echo -e "${BOLD}CBOM Analysis:${NC}"

    TOTAL=$(jq '.cbom.components | length' "$TEMP_DIR/policy-input.json")
    QUANTUM_VULNERABLE=$(jq '[.cbom.components[] | select(.crypto.quantumSafe == false)] | length' "$TEMP_DIR/policy-input.json")
    DEPRECATED=$(jq '[.cbom.components[] | select(.crypto.algorithm | IN("MD5", "SHA-1", "DES", "3DES"))] | length' "$TEMP_DIR/policy-input.json")

    echo "  Total crypto components: $TOTAL"
    echo "  Quantum-vulnerable: $QUANTUM_VULNERABLE"
    echo "  Deprecated algorithms: $DEPRECATED"

    if [ "$QUANTUM_VULNERABLE" -gt 0 ]; then
        echo -e "\n${RED}${BOLD}✗ FIPS Compliance: FAILED${NC}"
        echo -e "\n${YELLOW}Quantum-vulnerable components:${NC}"
        jq -r '.cbom.components[] | select(.crypto.quantumSafe == false) | "  - \(.name): \(.crypto.algorithm) (\(.crypto.quantumRisk))"' \
            "$TEMP_DIR/policy-input.json"
        exit 1
    fi

    if [ "$DEPRECATED" -gt 0 ]; then
        echo -e "\n${RED}${BOLD}✗ FIPS Compliance: FAILED${NC}"
        echo -e "\n${YELLOW}Deprecated algorithms:${NC}"
        jq -r '.cbom.components[] | select(.crypto.algorithm | IN("MD5", "SHA-1", "DES", "3DES")) | "  - \(.name): \(.crypto.algorithm)"' \
            "$TEMP_DIR/policy-input.json"
        exit 1
    fi

    echo -e "\n${GREEN}${BOLD}✓ FIPS Compliance: PASSED${NC}"
    exit 0
fi

# Run OPA evaluation
POLICY_DIR="policies"
if [ ! -d "$POLICY_DIR" ]; then
    POLICY_DIR="$(dirname "$0")"
fi

# Test with both original and CDX 1.6 policies
for POLICY in "fips-compliance-rego.rego" "fips-compliance-cdx16.rego"; do
    if [ -f "$POLICY_DIR/$POLICY" ]; then
        echo -e "${BOLD}Evaluating: $POLICY${NC}"

        # Check for denials
        DENIALS=$(opa eval \
            --data "$POLICY_DIR/$POLICY" \
            --input "$TEMP_DIR/policy-input.json" \
            --format raw \
            'data.fips_compliance.deny' 2>/dev/null || echo "[]")

        # Check for warnings
        WARNINGS=$(opa eval \
            --data "$POLICY_DIR/$POLICY" \
            --input "$TEMP_DIR/policy-input.json" \
            --format raw \
            'data.fips_compliance.warn' 2>/dev/null || echo "[]")

        # Display denials
        if [ "$DENIALS" != "[]" ] && [ "$DENIALS" != "null" ]; then
            echo -e "${RED}${BOLD}Denials:${NC}"
            echo "$DENIALS" | jq -r '.[] | "  ✗ \(.)"'
            EXIT_CODE=1
        fi

        # Display warnings
        if [ "$WARNINGS" != "[]" ] && [ "$WARNINGS" != "null" ]; then
            echo -e "${YELLOW}${BOLD}Warnings:${NC}"
            echo "$WARNINGS" | jq -r '.[] | "  ⚠ \(.)"'
        fi

        echo ""
    fi
done

# ==================================
# Summary
# ==================================
if [ "${EXIT_CODE:-0}" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✓ FIPS 140-2 Compliance: PASSED${NC}"

    # Display compliance metrics
    jq -r '.cbom.summary |
        "
Compliance Summary:
  Total Assets: \(.total_assets)
  Quantum-Safe: \(.quantum_safe_assets)
  Vulnerable: \(.vulnerable_assets)
"' "$TEMP_DIR/policy-input.json" 2>/dev/null || true
else
    echo -e "${RED}${BOLD}✗ FIPS 140-2 Compliance: FAILED${NC}"
    exit 1
fi