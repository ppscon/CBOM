#!/bin/bash
# Convert existing CBOM JSON file to CSV
# Usage: ./json-to-csv.sh input.json [output.csv]

set -e

JSON_FILE="$1"
OUTPUT_FILE="${2:-${JSON_FILE%.json}.csv}"

if [ -z "$JSON_FILE" ]; then
    echo "Usage: $0 <input.json> [output.csv]"
    echo "Examples:"
    echo "  $0 juice-shop.json"
    echo "  $0 juice-shop.json report.csv"
    exit 1
fi

if [ ! -f "$JSON_FILE" ]; then
    echo "Error: File not found: $JSON_FILE"
    exit 1
fi

# Check if file contains valid JSON
if ! jq empty "$JSON_FILE" 2>/dev/null; then
    echo "Error: $JSON_FILE does not contain valid JSON"
    echo "Contents:"
    head -5 "$JSON_FILE"
    exit 1
fi

# Convert to CSV using Python
CSV_OUTPUT=$(python3 -c "
import json
import sys

try:
    with open('$JSON_FILE', 'r') as f:
        data = json.load(f)

    # Print CSV header
    print('File,Algorithm,Type,Risk,Vulnerability,Description,Recommendation,NIST_Category,Security_Strength')

    # Check if findings exist and handle null case
    findings = data.get('findings', [])
    if findings is None:
        findings = []

    if not findings:
        print('Warning: No findings in JSON', file=sys.stderr)

    # Print findings
    for finding in findings:
        row = [
            finding.get('file', '').replace(',', ';'),
            finding.get('algorithm', ''),
            finding.get('type', ''),
            finding.get('risk', ''),
            finding.get('vulnerability_type', '').replace(',', ';'),
            finding.get('description', '').replace(',', ';'),
            finding.get('recommendation', '').replace(',', ';'),
            finding.get('nist_category', ''),
            str(finding.get('security_strength', ''))
        ]
        print(','.join(['\"' + str(field) + '\"' for field in row]))

except Exception as e:
    print('Error converting to CSV:', e, file=sys.stderr)
    sys.exit(1)
")

# Output to file
echo "$CSV_OUTPUT" > "$OUTPUT_FILE"
FINDING_COUNT=$(echo "$CSV_OUTPUT" | wc -l | tr -d ' ')
ACTUAL_COUNT=$((FINDING_COUNT - 1))  # Subtract header

echo "✓ CSV report saved to: $OUTPUT_FILE"
echo "  Found $ACTUAL_COUNT vulnerabilities"

# Show first few lines as preview
echo ""
echo "Preview:"
head -6 "$OUTPUT_FILE"
if [ "$ACTUAL_COUNT" -gt 5 ]; then
    echo "  ... and $((ACTUAL_COUNT - 5)) more"
fi