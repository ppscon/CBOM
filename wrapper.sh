#!/bin/sh
set -e

# Detect original scanner entrypoint
ORIGINAL_ENTRYPOINT=""
if [ -f "/usr/local/bin/trivy" ]; then
    ORIGINAL_ENTRYPOINT="/usr/local/bin/trivy"
elif [ -f "/scanner" ]; then
    ORIGINAL_ENTRYPOINT="/scanner"
else
    for potential in /usr/local/bin/* /usr/bin/*; do
        if [ -x "$potential" ] && [ "$potential" != "/wrapper.sh" ] && [ "$potential" != "/qvs-cbom" ]; then
            ORIGINAL_ENTRYPOINT="$potential"
            break
        fi
    done
fi

# Filter out --cbom flag and collect filtered arguments
FILTERED_ARGS=""
CBOM_REQUESTED=false

for arg in "$@"; do
    case "$arg" in
        --cbom|--CBOM|-cbom)
            CBOM_REQUESTED=true
            ;;
        *)
            FILTERED_ARGS="$FILTERED_ARGS $arg"
            ;;
    esac
done

# Run original scanner without --cbom flag
echo "Running original scanner..." >&2
$ORIGINAL_ENTRYPOINT $FILTERED_ARGS
SCANNER_EXIT_CODE=$?

# Generate CBOM if requested
if [ "$CBOM_REQUESTED" = true ]; then
    echo "Generating quantum CBOM..." >&2
    TARGET=""
    for arg in "$@"; do
        case "$arg" in
            --*|-*) ;;
            *) TARGET="$arg" ;;
        esac
    done
    
    if [ -n "$TARGET" ]; then
        /qvs-cbom -mode k8s -output-cbom "$TARGET" 2>/dev/null || echo "CBOM generation failed" >&2
    fi
fi

exit $SCANNER_EXIT_CODE