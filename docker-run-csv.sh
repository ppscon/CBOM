#!/bin/sh
set -eu
JSON=${1:-juice-shop.json}
OUT=${2:-juice-shop.csv}

if [ ! -f "$JSON" ]; then
  echo "File not found: $JSON" >&2
  exit 1
fi

# Prefer host-side conversion to avoid container entrypoint interference
if [ -x "./json-to-csv.sh" ]; then
  ./json-to-csv.sh "$JSON" "$OUT"
else
  echo "json-to-csv.sh not found or not executable" >&2
  exit 1
fi

echo "CSV written to $OUT"
