#!/bin/bash
#
# E2EE proxy entrypoint - renders the nginx config, prepares TLS material,
# and starts OpenResty in the foreground as the current (unprivileged) user.
#
# TLS modes (first match wins):
#   1. custom       TLS_CERT + TLS_KEY (+ optional TLS_CA) point to PEM files
#   2. self-signed  (default) generated at startup; persisted across restarts
#                   when TLS_STATE_DIR points at a writable, mounted directory
#
# Other knobs (all optional): see README "Configuration".
#
# Usage: entrypoint.sh            start the proxy
#        entrypoint.sh --check    render config + run `nginx -t`, then exit
#
set -euo pipefail

CHECK_ONLY=0
if [ "${1:-}" = "--check" ]; then
    CHECK_ONLY=1
fi

OPENRESTY_PREFIX=/usr/local/openresty/nginx
NGINX_BIN="$OPENRESTY_PREFIX/sbin/nginx"
CONF_SRC="$OPENRESTY_PREFIX/conf"
RUNTIME_DIR="${RUNTIME_DIR:-/tmp/e2ee}"

mkdir -p "$RUNTIME_DIR" "$RUNTIME_DIR/client_body" "$RUNTIME_DIR/proxy" \
         "$RUNTIME_DIR/fastcgi" "$RUNTIME_DIR/uwsgi" "$RUNTIME_DIR/scgi"
chmod 700 "$RUNTIME_DIR"

log()  { echo "[entrypoint] $*"; }
warn() { echo "[entrypoint] WARNING: $*" >&2; }
die()  { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------
SERVER_NAME="${TLS_DOMAIN:-_}"
DOMAIN="${TLS_DOMAIN:-localhost}"

if [ -n "${TLS_CERT:-}" ] && [ -n "${TLS_KEY:-}" ]; then
    TLS_MODE="custom"
    [ -r "$TLS_CERT" ] || die "TLS_CERT not readable: $TLS_CERT"
    [ -r "$TLS_KEY" ]  || die "TLS_KEY not readable: $TLS_KEY"
    cp "$TLS_CERT" "$RUNTIME_DIR/ssl.crt"
    if [ -n "${TLS_CA:-}" ]; then
        [ -r "$TLS_CA" ] || die "TLS_CA not readable: $TLS_CA"
        printf '\n' >> "$RUNTIME_DIR/ssl.crt"
        cat "$TLS_CA" >> "$RUNTIME_DIR/ssl.crt"
    fi
    cp "$TLS_KEY" "$RUNTIME_DIR/ssl.key"
    chmod 600 "$RUNTIME_DIR/ssl.key"
    log "TLS mode: custom certificate ($TLS_CERT)"
else
    TLS_MODE="self-signed"
    STATE_DIR="${TLS_STATE_DIR:-}"
    REUSED=0
    if [ -n "$STATE_DIR" ] && [ -s "$STATE_DIR/ssl.crt" ] && [ -s "$STATE_DIR/ssl.key" ]; then
        cp "$STATE_DIR/ssl.crt" "$RUNTIME_DIR/ssl.crt"
        cp "$STATE_DIR/ssl.key" "$RUNTIME_DIR/ssl.key"
        REUSED=1
    else
        # SAN covers the configured domain, localhost, loopback addresses and
        # e2ee-local-proxy.chutes.dev (a public A record for 127.0.0.1 that
        # existing client configs use).
        openssl req -x509 -newkey rsa:2048 -sha256 \
            -keyout "$RUNTIME_DIR/ssl.key" -out "$RUNTIME_DIR/ssl.crt" \
            -days 825 -nodes \
            -subj "/CN=$DOMAIN" \
            -addext "subjectAltName=DNS:$DOMAIN,DNS:localhost,DNS:e2ee-local-proxy.chutes.dev,IP:127.0.0.1,IP:::1" \
            -addext "basicConstraints=CA:FALSE" \
            -addext "extendedKeyUsage=serverAuth" \
            2>/dev/null || die "openssl failed to generate a self-signed certificate"
        if [ -n "$STATE_DIR" ]; then
            if mkdir -p "$STATE_DIR" 2>/dev/null && cp "$RUNTIME_DIR/ssl.crt" "$STATE_DIR/ssl.crt" \
               && cp "$RUNTIME_DIR/ssl.key" "$STATE_DIR/ssl.key"; then
                chmod 600 "$STATE_DIR/ssl.key" || true
            else
                warn "TLS_STATE_DIR=$STATE_DIR is not writable; certificate will not persist"
            fi
        fi
    fi
    chmod 600 "$RUNTIME_DIR/ssl.key"

    if [ "$CHECK_ONLY" = 0 ]; then
        log "TLS mode: self-signed certificate for $DOMAIN$( [ "$REUSED" = 1 ] && echo " (reused from $STATE_DIR)" )"
        cat <<EOF

  Clients must trust this certificate once. Extract it with:
    docker cp <container>:$RUNTIME_DIR/ssl.crt ./e2ee-proxy.crt
  macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain e2ee-proxy.crt
  Linux:   sudo cp e2ee-proxy.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
  Windows: Import-Certificate -FilePath e2ee-proxy.crt -CertStoreLocation Cert:\\LocalMachine\\Root
  Or point your client at it (e.g. SSL_CERT_FILE / REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS).
  For production use TLS_CERT/TLS_KEY, or mount TLS_STATE_DIR so the cert survives restarts.

EOF
    fi
fi

# ---------------------------------------------------------------------------
# Plaintext listener
# ---------------------------------------------------------------------------
ALLOW_PLAINTEXT="${ALLOW_PLAINTEXT:-false}"
PLAINTEXT_BIND_ADDR="${PLAINTEXT_BIND_ADDR:-0.0.0.0}"
case "$(echo "$ALLOW_PLAINTEXT" | tr '[:upper:]' '[:lower:]')" in
    true|1|yes|on)
        ALLOW_PLAINTEXT=true
        PLAINTEXT_LISTEN="$PLAINTEXT_BIND_ADDR:80"
        PLAINTEXT_BODY="include $RUNTIME_DIR/locations.inc;"
        ;;
    *)
        ALLOW_PLAINTEXT=false
        PLAINTEXT_LISTEN="80"
        PLAINTEXT_BODY='return 301 https://$host$request_uri;'
        ;;
esac

# ---------------------------------------------------------------------------
# Misc knobs
# ---------------------------------------------------------------------------
LOG_LEVEL="${LOG_LEVEL:-notice}"
case "$LOG_LEVEL" in
    debug|info|notice|warn|error|crit|alert|emerg) ;;
    *) warn "LOG_LEVEL=$LOG_LEVEL is not a valid nginx level; using notice"; LOG_LEVEL=notice ;;
esac

MAX_BODY_SIZE="${MAX_BODY_SIZE:-64m}"
if ! [[ "$MAX_BODY_SIZE" =~ ^[0-9]+[kmgKMG]?$ ]]; then
    warn "MAX_BODY_SIZE=$MAX_BODY_SIZE is not a valid nginx size; using 64m"
    MAX_BODY_SIZE=64m
fi

MODELS_BASE="${MODELS_BASE:-https://llm.chutes.ai}"
MODELS_BASE="${MODELS_BASE%/}"
MODELS_HOST="$(echo "$MODELS_BASE" | sed -E 's#^[a-zA-Z]+://##; s#[/?].*$##')"
[ -n "$MODELS_HOST" ] || die "cannot parse host from MODELS_BASE=$MODELS_BASE"

RESOLVERS="$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | grep -v ':' | tr '\n' ' ' | sed 's/ *$//')"
if [ -z "$RESOLVERS" ]; then
    RESOLVERS="8.8.8.8 1.1.1.1"
fi

# ---------------------------------------------------------------------------
# Render templates
# ---------------------------------------------------------------------------
render() {
    sed -e "s|__RUNTIME_DIR__|$RUNTIME_DIR|g" \
        -e "s|__RESOLVERS__|$RESOLVERS|g" \
        -e "s|__SERVER_NAME__|$SERVER_NAME|g" \
        -e "s|__LOG_LEVEL__|$LOG_LEVEL|g" \
        -e "s|__PLAINTEXT_LISTEN__|$PLAINTEXT_LISTEN|g" \
        -e "s|__PLAINTEXT_BODY__|$PLAINTEXT_BODY|g" \
        -e "s|__MAX_BODY_SIZE__|$MAX_BODY_SIZE|g" \
        -e "s|__MODELS_BASE__|$MODELS_BASE|g" \
        -e "s|__MODELS_HOST__|$MODELS_HOST|g" \
        "$1" > "$2"
}
render "$CONF_SRC/nginx.conf.template" "$RUNTIME_DIR/nginx.conf"
render "$CONF_SRC/locations.inc.template" "$RUNTIME_DIR/locations.inc"

if grep -q '__[A-Z_]*__' "$RUNTIME_DIR/nginx.conf" "$RUNTIME_DIR/locations.inc"; then
    die "unrendered placeholder left in config: $(grep -oh '__[A-Z_]*__' "$RUNTIME_DIR/nginx.conf" "$RUNTIME_DIR/locations.inc" | sort -u | tr '\n' ' ')"
fi

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
log "user=$(id -un 2>/dev/null || id -u) tls=$TLS_MODE server_name=$SERVER_NAME log_level=$LOG_LEVEL max_body=$MAX_BODY_SIZE"
log "route_mode=${ROUTE_MODE:-balanced} attestation=${E2EE_ATTEST:-observe} api_base=${API_BASE:-https://api.chutes.ai} models_base=$MODELS_BASE resolvers='$RESOLVERS'"
if [ "$ALLOW_PLAINTEXT" = true ]; then
    cat >&2 <<EOF
[entrypoint] ******************************************************************
[entrypoint] WARNING: ALLOW_PLAINTEXT=true - port 80 serves the API WITHOUT TLS.
[entrypoint]          API keys and prompts cross that hop in cleartext.
[entrypoint]          Publish it on loopback only:  docker run -p 127.0.0.1:8080:80 ...
[entrypoint]          (bind address inside the container: $PLAINTEXT_BIND_ADDR)
[entrypoint] ******************************************************************
EOF
fi
if [ "${E2EE_ATTEST:-observe}" = "observe" ]; then
    warn "E2EE_ATTEST=observe: attestation results are logged but not enforced (see README)."
fi

NGINX_ARGS=(-p "$OPENRESTY_PREFIX" -c "$RUNTIME_DIR/nginx.conf" -e /dev/stderr)

if [ "$CHECK_ONLY" = 1 ]; then
    exec "$NGINX_BIN" "${NGINX_ARGS[@]}" -t
fi

exec "$NGINX_BIN" "${NGINX_ARGS[@]}" -g "daemon off;"
