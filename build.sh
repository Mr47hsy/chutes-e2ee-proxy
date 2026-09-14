#!/usr/bin/env bash
#
# Build the e2ee-proxy Docker image.
#
#   ./build.sh                       # Debian bookworm base (Dockerfile), linux/amd64, tag e2ee-proxy
#   ./build.sh --alpine              # Alpine base (Dockerfile.alpine)
#   ./build.sh --tag myrepo/e2ee-proxy:1.0
#   ./build.sh --mlkem-backend kyber-r3   # only if end-to-end tests show the
#                                         # instances speak Kyber round-3
#
# This is a thin wrapper around `docker build`; nothing outside this
# repository is needed (no xvmp, no certificates).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG="${TAG:-e2ee-proxy}"
PLATFORM="${PLATFORM:-linux/amd64}"
MLKEM_BACKEND="${MLKEM_BACKEND:-pqclean-ml-kem-768}"
DOCKERFILE="${DOCKERFILE:-Dockerfile}"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)            TAG="$2"; shift 2 ;;
        --platform)       PLATFORM="$2"; shift 2 ;;
        --mlkem-backend)  MLKEM_BACKEND="$2"; shift 2 ;;
        --alpine)         DOCKERFILE="Dockerfile.alpine"; shift ;;
        --debian)         DOCKERFILE="Dockerfile"; shift ;;   # kept for compatibility; Debian is the default
        --dockerfile)     DOCKERFILE="$2"; shift 2 ;;
        --no-cache)       EXTRA_ARGS+=("--no-cache"); shift ;;
        --progress)       EXTRA_ARGS+=("--progress" "$2"); shift 2 ;;
        -h|--help)        sed -n '2,14p' "$0"; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

echo "=== Building $TAG ($PLATFORM, $DOCKERFILE, MLKEM_BACKEND=$MLKEM_BACKEND) ==="
docker build \
    --platform "$PLATFORM" \
    --build-arg "PLATFORM=$PLATFORM" \
    --build-arg "MLKEM_BACKEND=$MLKEM_BACKEND" \
    -f "$SCRIPT_DIR/$DOCKERFILE" \
    -t "$TAG" \
    "${EXTRA_ARGS[@]}" \
    "$SCRIPT_DIR"

cat <<EOF

=== Build complete: $TAG ===

Run (self-signed TLS, balanced routing, attestation enforced):
  docker run --rm -p 8443:443 $TAG

Then trust the certificate (printed at startup) and point clients at
  https://localhost:8443/v1   or   https://e2ee-local-proxy.chutes.dev:8443/v1
EOF
