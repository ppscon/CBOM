#!/bin/bash
# QVS-CBOM CSV Output Wrapper
# Usage: ./qvs-cbom-csv.sh <target> [--output filename.csv]

set -e

TARGET="$1"
OUTPUT_FILE=""

# Parse arguments
shift
while [[ $# -gt 0 ]]; do
    case $1 in
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [--output filename.csv]"
    echo "Examples:"
    echo "  $0 test-app.py --output report.csv"
    echo "  $0 nginx:latest --output container-report.csv"
    exit 1
fi

# Generate CBOM JSON
JSON_OUTPUT=$(./qvs-cbom -mode file -dir "$TARGET" -output-cbom 2>/dev/null)

# Convert to CSV using Python
CSV_OUTPUT=$(python3 -c "
import json
import sys

try:
    data = json.loads('''$JSON_OUTPUT''')
    
    # Print CSV header
    print('File,Algorithm,Type,Risk,Vulnerability,Description,Recommendation,NIST_Category,Security_Strength')
    
    # Print findings
    for finding in data.get('findings', []):
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

# Output to file or stdout
if [ -n "$OUTPUT_FILE" ]; then
    echo "$CSV_OUTPUT" > "$OUTPUT_FILE"
    echo "✓ CSV report saved to: $OUTPUT_FILE"
    echo "  Found $(echo "$CSV_OUTPUT" | wc -l | tr -d ' ') vulnerabilities (including header)"
else
    echo "$CSV_OUTPUT"
fi