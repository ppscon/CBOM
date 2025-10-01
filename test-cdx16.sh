#!/usr/bin/env bash
set -euo pipefail

# Test script for CycloneDX 1.6 upgrade

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}Testing CycloneDX 1.6 Upgrade${NC}\n"

# Test 1: Generate 1.6 CBOM using Docker wrapper
echo -e "${CYAN}[1/4] Testing CBOM generation with CBOM_CDX_TARGET=1.6${NC}"
mkdir -p outputs
OUTPUT_FILE="outputs/juice-shop-cdx16.json"

echo "  Running: docker run with CBOM_CDX_TARGET=1.6 and CBOM_OUTPUT_FILE=/out/juice-shop-cdx16.json"
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/outputs":/out \
  -e CBOM_CDX_TARGET=1.6 \
  -e CBOM_OUTPUT_FILE=/out/juice-shop-cdx16.json \
  enhanced-scanner --CBOM image bkimminich/juice-shop:latest 2>&1 | tail -10

echo ""
if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
    echo -e "${GREEN}✓ CBOM file generated: $OUTPUT_FILE${NC}"
else
    echo -e "${RED}✗ CBOM file not found at: $OUTPUT_FILE${NC}"
    exit 1
fi

# Test 2: Verify specVersion is 1.6
echo -e "\n${CYAN}[2/4] Verifying specVersion field${NC}"
SPEC_VERSION=$(jq -r '.specVersion' "$OUTPUT_FILE")
if [ "$SPEC_VERSION" = "1.6" ]; then
    echo -e "${GREEN}✓ specVersion is 1.6${NC}"
else
    echo -e "${RED}✗ Expected specVersion 1.6, got: $SPEC_VERSION${NC}"
    exit 1
fi

# Test 3: Verify component.properties exist
echo -e "\n${CYAN}[3/4] Verifying component.properties mappings${NC}"
HAS_PROPS=$(jq '[.components[]? | select(.properties != null)] | length' "$OUTPUT_FILE")
HAS_CRYPTO=$(jq '[.components[]? | select(.crypto != null)] | length' "$OUTPUT_FILE")

echo "  Components with .properties: $HAS_PROPS"
echo "  Components with .crypto: $HAS_CRYPTO"

if [ "$HAS_PROPS" -gt 0 ]; then
    echo -e "${GREEN}✓ Properties found on components${NC}"

    # Show sample property
    echo -e "\n${CYAN}Sample component.properties:${NC}"
    jq '.components[0].properties[]? | select(.name | startswith("cbom:")) | {name, value}' "$OUTPUT_FILE" | head -20
else
    echo -e "${YELLOW}⚠ No components have properties array${NC}"
fi

# Test 4: Validate property keys
echo -e "\n${CYAN}[4/4] Validating CBOM property names${NC}"
REQUIRED_PROPS=("cbom:algorithm" "cbom:purpose" "cbom:quantumRisk" "cbom:quantumSafe")
FOUND_ALL=true

for prop in "${REQUIRED_PROPS[@]}"; do
    COUNT=$(jq "[.components[]?.properties[]? | select(.name == \"$prop\")] | length" "$OUTPUT_FILE")
    if [ "$COUNT" -gt 0 ]; then
        echo -e "  ${GREEN}✓${NC} $prop found ($COUNT times)"
    else
        echo -e "  ${RED}✗${NC} $prop not found"
        FOUND_ALL=false
    fi
done

# Summary
echo -e "\n${CYAN}═══════════════════════════════════════${NC}"
if [ "$FOUND_ALL" = true ]; then
    echo -e "${GREEN}${BOLD}✓ All CycloneDX 1.6 tests passed!${NC}"
    echo -e "\n${BOLD}Generated CBOM:${NC} ${CYAN}$OUTPUT_FILE${NC}"
    echo -e "${BOLD}Spec Version:${NC} 1.6"
    echo -e "${BOLD}Format:${NC} CycloneDX with component.properties"
else
    echo -e "${RED}${BOLD}✗ CycloneDX 1.6 validation failed${NC}"
    exit 1
fi