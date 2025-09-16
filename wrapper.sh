#!/bin/sh
set -e

# Original scanner entrypoint; override via ORIGINAL_ENTRYPOINT if needed.
ORIGINAL_ENTRYPOINT=${ORIGINAL_ENTRYPOINT:-/usr/local/bin/trivy}

if [ ! -x "$ORIGINAL_ENTRYPOINT" ]; then
    echo "Original scanner entrypoint not found: $ORIGINAL_ENTRYPOINT" >&2
    exit 1
fi

# Filter out the --CBOM flag while keeping the remaining arguments intact.
CBOM_REQUESTED=false
FILTERED_ARGS=""
ORIGINAL_ARGS_COPY="$*"

for arg in "$@"; do
    case "$arg" in
        --CBOM|--cbom)
            CBOM_REQUESTED=true
            ;;
        *)
            if [ -z "$FILTERED_ARGS" ]; then
                FILTERED_ARGS="$arg"
            else
                FILTERED_ARGS="$FILTERED_ARGS $arg"
            fi
            ;;
    esac
done

if [ -n "$FILTERED_ARGS" ]; then
    # shellcheck disable=SC2086
    set -- $FILTERED_ARGS
else
    set --
fi

# Run the original scanner first.
set +e
"$ORIGINAL_ENTRYPOINT" "$@"
SCANNER_EXIT_CODE=$?
set -e

# Helper to run the CBOM binary and preserve the scanner's exit behaviour.
run_cbom_command() {
    if [ "$#" -eq 0 ]; then
        return 0
    fi

    echo "Running /qvs-cbom $*" >&2
    set +e
    /qvs-cbom "$@"
    CBOM_EXIT=$?
    set -e

    if [ $CBOM_EXIT -ne 0 ]; then
        echo "CBOM generation failed with exit code $CBOM_EXIT" >&2
    fi
}

extract_image_rootfs() {
    image_ref="$1"

    if ! command -v docker >/dev/null 2>&1; then
        echo "CBOM wrapper: docker CLI not available inside container. Install docker-cli in the image." >&2
        return 1
    fi

    if [ ! -S /var/run/docker.sock ] && [ -z "$DOCKER_HOST" ]; then
        echo "CBOM wrapper: Docker socket not mounted. Run container with -v /var/run/docker.sock:/var/run/docker.sock" >&2
        return 1
    fi

    tmp_dir=$(mktemp -d /tmp/cbom-image-XXXXXX) || return 1

    if ! cid=$(docker create "$image_ref" 2>/dev/null); then
        echo "CBOM wrapper: unable to create container from $image_ref" >&2
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! docker export "$cid" 2>/dev/null | tar -C "$tmp_dir" -xf - 2>/dev/null; then
        echo "CBOM wrapper: failed to export filesystem for $image_ref" >&2
        docker rm "$cid" >/dev/null 2>&1 || true
        rm -rf "$tmp_dir"
        return 1
    fi

    docker rm "$cid" >/dev/null 2>&1 || true

    printf '%s\n' "$tmp_dir"
    return 0
}

# Execute the CBOM workflow if requested.
if [ "$CBOM_REQUESTED" = true ]; then
    echo "Detected --CBOM flag" >&2

    if [ -n "$CBOM_COMMAND_TEMPLATE" ]; then
        echo "Running custom CBOM command: $CBOM_COMMAND_TEMPLATE" >&2
        CBOM_ORIGINAL_ARGS="$ORIGINAL_ARGS_COPY" sh -c "$CBOM_COMMAND_TEMPLATE"
    else
        PRIMARY_CMD=${1:-}
        case "$PRIMARY_CMD" in
            image|IMAGE|i|I)
                shift || true
                IMAGE_TARGET=""
                for token in "$@"; do
                    IMAGE_TARGET="$token"
                done

                if [ -z "$IMAGE_TARGET" ] || [ "${IMAGE_TARGET#-}" != "$IMAGE_TARGET" ]; then
                    echo "CBOM wrapper: no image target supplied; skipping." >&2
                else
                    IMAGE_DIR=$(extract_image_rootfs "$IMAGE_TARGET") || IMAGE_DIR=""
                    if [ -n "$IMAGE_DIR" ]; then
                        run_cbom_command -mode file -dir "$IMAGE_DIR" -output-cbom
                        rm -rf "$IMAGE_DIR"
                    fi
                fi
                ;;
            filesystem|fs|FILESYSTEM|FS)
                shift || true
                TARGET_PATH=${1:-.}
                run_cbom_command -mode file -dir "$TARGET_PATH" -output-cbom
                ;;
            kubernetes|k8s|KUBERNETES|K8S)
                shift || true
                NAMESPACE=${CBOM_NAMESPACE:-}
                PREV=""
                while [ "$#" -gt 0 ]; do
                    case "$1" in
                        --namespace=*)
                            NAMESPACE=${1#--namespace=}
                            ;;
                        -n|--namespace)
                            PREV="$1"
                            ;;
                        *)
                            if [ "$PREV" = "-n" ] || [ "$PREV" = "--namespace" ]; then
                                NAMESPACE="$1"
                                PREV=""
                            fi
                            ;;
                    esac
                    shift || true
                done

                if [ "$PREV" = "-n" ] || [ "$PREV" = "--namespace" ]; then
                    echo "CBOM wrapper: namespace flag provided without value; skipping." >&2
                else
                    if [ -n "$NAMESPACE" ]; then
                        run_cbom_command -mode k8s -namespace "$NAMESPACE" -output-cbom
                    else
                        run_cbom_command -mode k8s -output-cbom
                    fi
                fi
                ;;
            "")
                echo "CBOM wrapper: no arguments provided to scanner; skipping." >&2
                ;;
            *)
                echo "CBOM wrapper: no handler for '$PRIMARY_CMD'; set CBOM_COMMAND_TEMPLATE to customize." >&2
                ;;
        esac
    fi
fi

exit "$SCANNER_EXIT_CODE"
