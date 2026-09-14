#!/usr/bin/env bash
#
# Run the integration suite locally against a built image, the same way CI does:
# mock upstream on the host, three proxy containers (observe / enforce / small
# body limit) pointed at it, then pytest.
#
#   tests/integration/run_local.sh                 # image e2ee-proxy
#   IMAGE=e2ee-proxy:debian tests/integration/run_local.sh
#   tests/integration/run_local.sh --keep          # leave containers running
#   PYTHON=/path/to/venv/bin/python tests/integration/run_local.sh
#
# Requires: docker, python with tests/integration/requirements.txt installed.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${IMAGE:-e2ee-proxy}"
PYTHON="${PYTHON:-python3}"
MOCK_PORT="${MOCK_PORT:-9100}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

LOG_DIR="${LOG_DIR:-$ROOT/tests/integration/.logs}"
mkdir -p "$LOG_DIR"

cleanup() {
    if [ "$KEEP" = 1 ]; then
        echo "--keep: containers proxy-observe/proxy-enforce/proxy-small and the mock (pid $MOCK_PID) left running"
        return
    fi
    docker rm -f proxy-observe proxy-enforce proxy-small >/dev/null 2>&1 || true
    kill "$MOCK_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f proxy-observe proxy-enforce proxy-small >/dev/null 2>&1 || true

echo "=== mock upstream on :$MOCK_PORT ==="
"$PYTHON" "$ROOT/tests/integration/mock_upstream.py" --port "$MOCK_PORT" > "$LOG_DIR/mock.log" 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:$MOCK_PORT/_mock/stats" >/dev/null && break
    sleep 1
done
curl -sf "http://127.0.0.1:$MOCK_PORT/_mock/stats" >/dev/null || { echo "mock did not start"; cat "$LOG_DIR/mock.log"; exit 1; }

COMMON=(--add-host=host.docker.internal:host-gateway
        -e "API_BASE=http://host.docker.internal:$MOCK_PORT"
        -e "MODELS_BASE=http://host.docker.internal:$MOCK_PORT"
        -e LOG_LEVEL=info)

echo "=== proxies ($IMAGE) ==="
docker run -d --name proxy-observe -p 8443:443 "${COMMON[@]}" -e E2EE_ATTEST=observe "$IMAGE" >/dev/null
docker run -d --name proxy-enforce -p 8444:443 "${COMMON[@]}" \
    -e E2EE_ATTEST=enforce -e E2EE_ATTEST_TTL=1 -e E2EE_ATTEST_FAIL_TTL=0 "$IMAGE" >/dev/null
docker run -d --name proxy-small -p 8445:443 "${COMMON[@]}" -e E2EE_ATTEST=observe -e MAX_BODY_SIZE=1m "$IMAGE" >/dev/null

for p in 8443 8444 8445; do
    ok=0
    for _ in $(seq 1 40); do
        if curl -skf "https://127.0.0.1:$p/health" >/dev/null 2>&1; then ok=1; break; fi
        sleep 1
    done
    if [ "$ok" != 1 ]; then
        echo "proxy on :$p did not become healthy"
        for n in proxy-observe proxy-enforce proxy-small; do echo "--- $n"; docker logs "$n" 2>&1 | tail -40; done
        exit 1
    fi
    echo "  :$p healthy -> $(curl -sk "https://127.0.0.1:$p/health")"
done

echo "=== pytest ==="
set +e
PROXY_URL=https://127.0.0.1:8443 PROXY_ENFORCE_URL=https://127.0.0.1:8444 \
PROXY_SMALL_BODY_URL=https://127.0.0.1:8445 MOCK_URL="http://127.0.0.1:$MOCK_PORT" \
    "$PYTHON" -m pytest -q "$ROOT/tests/integration/test_proxy.py" "$@"
RC=$?
set -e

for n in proxy-observe proxy-enforce proxy-small; do
    docker logs "$n" > "$LOG_DIR/$n.log" 2>&1 || true
done

echo "=== API-key leak scan on proxy logs ==="
if grep -q "cpk_integration" "$LOG_DIR"/proxy-*.log; then
    echo "FAIL: API key material found in proxy logs"; RC=1
else
    echo "ok: no API key material in logs"
fi
echo "logs in $LOG_DIR"
exit $RC
