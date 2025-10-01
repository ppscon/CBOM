#!/bin/sh
# Aqua-CBOM CSV Output Helper (self-contained)
# Usage:
#  - Convert existing JSON: ./aqua-cbom-csv.sh input.json --output report.csv
#  - Scan a directory and convert: ./aqua-cbom-csv.sh /path/to/dir --output report.csv
set -eu

TARGET="${1:-}"
OUTPUT_FILE=""

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <input.json|directory> [--output filename.csv]"
    exit 1
fi

shift || true
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT_FILE="$2"
            shift 2 || true
            ;;
        *)
            shift || true
            ;;
    esac
done

# Helper: convert JSON (file path provided) to CSV using Python
convert_json_to_csv() {
    JSON_FILE="$1"
    [ -n "${OUTPUT_FILE:-}" ] || OUTPUT_FILE="${JSON_FILE%.json}.csv"
    python3 - "$JSON_FILE" <<'PY'
import json, sys
json_path = sys.argv[1]
with open(json_path, 'r') as f:
    data = json.load(f)
print('File,Algorithm,Type,Risk,Vulnerability,Description,Recommendation,NIST_Category,Security_Strength')
findings = data.get('findings') or []
for finding in findings:
    row = [
        (finding.get('file') or '').replace(',', ';'),
        finding.get('algorithm') or '',
        finding.get('type') or '',
        finding.get('risk') or '',
        (finding.get('vulnerability_type') or '').replace(',', ';'),
        (finding.get('description') or '').replace(',', ';'),
        (finding.get('recommendation') or '').replace(',', ';'),
        str(finding.get('nist_category') or ''),
        str(finding.get('security_strength') or '')
    ]
    print(','.join('"%s"' % v for v in row))
PY
}

# Case 1: input is a JSON file
if [ -f "$TARGET" ] && [ "${TARGET##*.}" = "json" ]; then
    convert_json_to_csv "$TARGET" > "$OUTPUT_FILE"
    echo "✓ CSV report saved to: $OUTPUT_FILE"
    exit 0
fi

# Case 2: input is a directory -> run scanner and convert
if [ -d "$TARGET" ] || [ -f "$TARGET" ]; then
    # Detect binary name (prefer aqua-cbom, fallback to qvs-cbom)
    if [ -f "./aqua-cbom" ]; then
        CBOM_BIN="./aqua-cbom"
    elif [ -f "./qvs-cbom" ]; then
        echo "⚠️  WARNING: qvs-cbom is deprecated, please rename to aqua-cbom" >&2
        CBOM_BIN="./qvs-cbom"
    else
        echo "Error: aqua-cbom binary not found" >&2
        exit 1
    fi

    CBOM_TMP="$(mktemp -t cbom-XXXXXX.json)"
    set +e
    CBOM_JSON="$($CBOM_BIN -mode file -dir "$TARGET" -output-cbom 2>/dev/null)"
    SCAN_EXIT=$?
    set -e
    if [ $SCAN_EXIT -ne 0 ] || [ -z "$CBOM_JSON" ]; then
        echo "Failed to generate CBOM for: $TARGET" >&2
        exit 1
    fi
    printf '%s\n' "$CBOM_JSON" > "$CBOM_TMP"
    [ -n "${OUTPUT_FILE:-}" ] || OUTPUT_FILE="report.csv"
    convert_json_to_csv "$CBOM_TMP" > "$OUTPUT_FILE"
    rm -f "$CBOM_TMP"
    echo "✓ CSV report saved to: $OUTPUT_FILE"
    exit 0
fi

echo "Error: Target not found or unsupported: $TARGET" >&2
exit 1