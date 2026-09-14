#!/usr/bin/env bash
#
# End-to-end acceptance against the REAL Chutes API through a running proxy.
# This is the only test that proves the ML-KEM variant interoperates
# (README "Verifying the ML-KEM variant").
#
#   CHUTES_API_KEY=cpk_... tests/e2e_real.sh
#   PROXY_URL=https://127.0.0.1:8443 MODEL=moonshotai/Kimi-K3-TEE tests/e2e_real.sh
#
# The key is read from the environment and never echoed.
#
set -euo pipefail

: "${CHUTES_API_KEY:?set CHUTES_API_KEY (cpk_...)}"
PROXY_URL="${PROXY_URL:-https://127.0.0.1:8443}"
# Cheapest plain-instruct TEE model at the time of writing; override with MODEL=...
MODEL="${MODEL:-unsloth/Mistral-Nemo-Instruct-2407-TEE}"
CURL=(curl -sk --max-time 180 -H "Authorization: Bearer $CHUTES_API_KEY" -H "Content-Type: application/json")

step() { printf '\n=== %s ===\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

step "health"
health=$(curl -sk --max-time 10 "$PROXY_URL/health") || fail "proxy not reachable at $PROXY_URL"
echo "$health"

step "GET /v1/models (TLS passthrough, not E2EE) contains $MODEL"
models=$("${CURL[@]}" "$PROXY_URL/v1/models")
if ! echo "$models" | grep -q "\"id\":\"$MODEL\""; then
    echo "available TEE models:"
    echo "$models" | grep -o '"id":"[^"]*-TEE"' | sed 's/"id":"//; s/"$//' | sort | sed 's/^/  /'
    fail "model '$MODEL' not listed; pick one above with MODEL=..."
fi
echo "ok"

step "non-streaming chat completion (E2EE)"
body=$(printf '{"model":"%s","messages":[{"role":"user","content":"Reply with exactly: pong"}],"max_tokens":16}' "$MODEL")
resp_headers=$(mktemp); trap 'rm -f "$resp_headers"' EXIT
resp=$("${CURL[@]}" -D "$resp_headers" -d "$body" "$PROXY_URL/v1/chat/completions")
status=$(awk 'NR==1{print $2}' "$resp_headers")
echo "status=$status instance=$(grep -i '^x-e2ee-instance-id' "$resp_headers" | tr -d '\r' | cut -d' ' -f2-) mode=$(grep -i '^x-e2ee-route-mode' "$resp_headers" | tr -d '\r' | cut -d' ' -f2-) rid=$(grep -i '^x-request-id' "$resp_headers" | tr -d '\r' | cut -d' ' -f2-)"
if [ "$status" != "200" ]; then
    echo "$resp" | head -c 600; echo
    cat <<'EOF'

Upstream rejected or could not decrypt the request. If /health and /v1/models
are fine and the proxy log shows a successful /e2e/instances fetch, the most
likely cause is the ML-KEM variant (FIPS 203 vs Kyber round-3): see
native/mlkem/README.md and rebuild with ./build.sh --mlkem-backend kyber-r3.
EOF
    exit 1
fi
echo "$resp" | head -c 600; echo
echo "$resp" | grep -q '"choices"' || fail "response is not a chat completion"
echo "usage: $(echo "$resp" | grep -o '"usage":{[^}]*}[^}]*}' | head -c 300)"

step "streaming chat completion (E2EE, e2e-stream-v1 key path)"
sbody=$(printf '{"model":"%s","messages":[{"role":"user","content":"Count from 1 to 5, one number per line."}],"max_tokens":64,"stream":true}' "$MODEL")
stream=$("${CURL[@]}" -N -d "$sbody" "$PROXY_URL/v1/chat/completions")
n_chunks=$(echo "$stream" | grep -c '^data: {' || true)
echo "$stream" | grep -q '^data: \[DONE\]' || { echo "$stream" | head -c 600; echo; fail "stream did not end with [DONE]"; }
echo "$stream" | grep -q '"e2e"' && fail "encrypted chunk leaked to client"
echo "chunks=$n_chunks"
echo "$stream" | grep '^data: {' | sed 's/^data: //' | grep -o '"content":"[^"]*"' | tr -d '\n' | head -c 300; echo

step "attestation evidence shape (GET /chutes/{chute_id}/evidence, strings truncated)"
API_BASE="${API_BASE:-https://api.chutes.ai}"
chute_id=$(echo "$models" | python3 -c "
import sys, json
for m in json.load(sys.stdin)['data']:
    if m['id'] == '$MODEL':
        print(m.get('chute_id', '')); break")
if [ -n "$chute_id" ]; then
    nonce_hex=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    "${CURL[@]}" "$API_BASE/chutes/$chute_id/evidence?nonce=$nonce_hex" | python3 -c "
import sys, json
def shape(v, d=0):
    if isinstance(v, dict):
        return '{' + ', '.join(f'{k}: {shape(x, d+1)}' for k, x in list(v.items())[:30]) + '}'
    if isinstance(v, list):
        return f'[{len(v)} items' + (': ' + shape(v[0], d+1) if v else '') + ']'
    if isinstance(v, str):
        return repr(v) if len(v) <= 48 else f'str[{len(v)}]'
    return repr(v)
try:
    print(shape(json.load(sys.stdin)))
except Exception as e:
    print('non-JSON or empty evidence response:', e)"
else
    echo "(chute_id for $MODEL not found in model list)"
fi

step "proxy metrics (attestation / cache / errors)"
curl -sk --max-time 10 "$PROXY_URL/metrics" | grep -E '^e2ee_(attestation_total|upstream_errors_total|cache_events_total|requests_total|instance_picks_total)' || true

step "attestation log lines from the container (if run via docker)"
cid=$(docker ps -q --filter "ancestor=e2ee-proxy" 2>/dev/null | head -1 || true)
if [ -n "$cid" ]; then
    docker logs "$cid" 2>&1 | grep -iE "attestation|ATTESTATION" | tail -5 || echo "(no attestation lines yet)"
fi

echo; echo "ALL GOOD: non-streaming and streaming E2EE round trips succeeded against the real API."
