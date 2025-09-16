#!/usr/bin/env bash
set -euo pipefail

IMAGE=${ENHANCED_SCANNER_IMAGE:-enhanced-scanner}
DOCKER_SOCK=${DOCKER_SOCK_PATH:-/var/run/docker.sock}
KUBECONFIG_DIR=${KUBECONFIG_DIR:-$HOME/.kube}
NAMESPACE=${CBOM_NAMESPACE:-cbom}
TARGET_IMAGE=${CBOM_TARGET_IMAGE:-bkimminich/juice-shop:latest}

usage() {
  cat <<USAGE
Usage: $0 <juice|k8s>

  juice   Scan the Juice Shop demo container (default: $TARGET_IMAGE)
  k8s     Scan the Kubernetes namespace (default: $NAMESPACE)

Environment overrides:
  ENHANCED_SCANNER_IMAGE  Name/tag of the wrapped image (default: enhanced-scanner)
  DOCKER_SOCK_PATH        Path to the Docker socket (default: /var/run/docker.sock)
  CBOM_NAMESPACE          Namespace to scan for the k8s demo (default: cbom)
  CBOM_TARGET_IMAGE       Container image to scan for the juice demo
  KUBECONFIG_DIR          Directory containing kubeconfig files (default: $HOME/.kube)
USAGE
}

require_socket() {
  if [ ! -S "$DOCKER_SOCK" ]; then
    echo "Docker socket not found at $DOCKER_SOCK. Export DOCKER_SOCK_PATH to override." >&2
    exit 1
  fi
}

run_juice() {
  require_socket
  docker run --rm \
    -v "$DOCKER_SOCK":"$DOCKER_SOCK" \
    -e DOCKER_HOST="${DOCKER_HOST:-}" \
    "$IMAGE" --CBOM image "$TARGET_IMAGE"
}

run_k8s() {
  require_socket
  if [ ! -d "$KUBECONFIG_DIR" ]; then
    echo "Kubeconfig directory $KUBECONFIG_DIR not found. Export KUBECONFIG_DIR to override." >&2
    exit 1
  fi

  docker run --rm \
    -v "$DOCKER_SOCK":"$DOCKER_SOCK" \
    -v "$KUBECONFIG_DIR":/root/.kube \
    -e DOCKER_HOST="${DOCKER_HOST:-}" \
    "$IMAGE" --CBOM kubernetes --namespace "$NAMESPACE"
}

case "${1:-}" in
  juice)
    run_juice
    ;;
  k8s)
    run_k8s
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
