#!/usr/bin/env bash
#
# Build libe2ee_proxy.so with a plain C compiler. No LLVM passes, no packer,
# no certificate material.
#
# Usage:
#   ./build.sh                 # -> $OUT_DIR/libe2ee_proxy.so (or .dylib on macOS)
#   ./build.sh --selftest      # additionally build and run the self-test binary
#
# Environment:
#   CC              C compiler (default: cc)
#   OUT_DIR         output directory (default: ./out)
#   MLKEM_BACKEND   pqclean-ml-kem-768 (default, FIPS 203) | kyber-r3 (round-3 fallback)
#   OPENSSL_DIR     prefix of an OpenSSL install if not on the default search path
#   EXTRA_CFLAGS    appended to CFLAGS
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/out}"
MLKEM_BACKEND="${MLKEM_BACKEND:-pqclean-ml-kem-768}"
RUN_SELFTEST=0
for arg in "$@"; do
    case "$arg" in
        --selftest) RUN_SELFTEST=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

MLKEM_DIR="$SCRIPT_DIR/mlkem"
COMMON_DIR="$MLKEM_DIR/common"

CFLAGS="-O2 -fPIC -std=c99 -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden -D_GNU_SOURCE"
CFLAGS="$CFLAGS ${EXTRA_CFLAGS:-}"
LDLIBS="-lcrypto -lz"

if [ -n "${OPENSSL_DIR:-}" ]; then
    CFLAGS="$CFLAGS -I$OPENSSL_DIR/include"
    LDLIBS="-L$OPENSSL_DIR/lib $LDLIBS"
fi

case "$MLKEM_BACKEND" in
    pqclean-ml-kem-768)
        BACKEND_DIR="$MLKEM_DIR/pqclean-ml-kem-768"
        BACKEND_DEFINE="-DE2EE_MLKEM_BACKEND_PQCLEAN=1"
        BACKEND_SRCS=("$BACKEND_DIR"/*.c "$COMMON_DIR/fips202.c")
        ;;
    kyber-r3)
        BACKEND_DIR="$MLKEM_DIR/kyber-r3"
        BACKEND_DEFINE="-DE2EE_MLKEM_BACKEND_KYBER_R3=1 -DKYBER_K=3"
        if [ ! -f "$BACKEND_DIR/kem.c" ]; then
            echo "ERROR: MLKEM_BACKEND=kyber-r3 but $BACKEND_DIR/kem.c is missing." >&2
            echo "       See native/mlkem/README.md for how to vendor the round-3 sources." >&2
            exit 1
        fi
        BACKEND_SRCS=("$BACKEND_DIR"/*.c)
        ;;
    *)
        echo "ERROR: unknown MLKEM_BACKEND '$MLKEM_BACKEND'" >&2
        exit 1
        ;;
esac

UNAME="$(uname -s)"
if [ "$UNAME" = "Darwin" ]; then
    SO_NAME="libe2ee_proxy.dylib"
    SHARED_FLAGS="-dynamiclib -Wl,-exported_symbols_list,$SCRIPT_DIR/exports.macos"
    if [ -z "${OPENSSL_DIR:-}" ] && command -v brew >/dev/null 2>&1; then
        BREW_SSL="$(brew --prefix openssl@3 2>/dev/null || true)"
        if [ -n "$BREW_SSL" ]; then
            CFLAGS="$CFLAGS -I$BREW_SSL/include"
            LDLIBS="-L$BREW_SSL/lib $LDLIBS"
        fi
    fi
else
    SO_NAME="libe2ee_proxy.so"
    SHARED_FLAGS="-shared -Wl,--version-script=$SCRIPT_DIR/exports.map -Wl,-z,relro -Wl,-z,now -Wl,--no-undefined"
fi

OBJ_DIR="$(mktemp -d)"
trap 'rm -rf "$OBJ_DIR"' EXIT
mkdir -p "$OUT_DIR"

echo "=== e2ee native build ==="
echo "  CC            = $CC"
echo "  MLKEM_BACKEND = $MLKEM_BACKEND"
echo "  OUT_DIR       = $OUT_DIR"

INCLUDES="-I$SCRIPT_DIR -I$BACKEND_DIR -I$COMMON_DIR"

compile() {
    local src="$1" obj="$2" extra="${3:-}"
    # shellcheck disable=SC2086
    "$CC" $CFLAGS $extra $INCLUDES -c -o "$obj" "$src"
}

OBJS=()
i=0
for src in "${BACKEND_SRCS[@]}"; do
    obj="$OBJ_DIR/mlkem_$i.o"
    compile "$src" "$obj" "$BACKEND_DEFINE"
    OBJS+=("$obj")
    i=$((i + 1))
done

compile "$SCRIPT_DIR/randombytes.c" "$OBJ_DIR/randombytes.o"
compile "$SCRIPT_DIR/e2ee_proxy_api.c" "$OBJ_DIR/e2ee_proxy_api.o" "$BACKEND_DEFINE"
OBJS+=("$OBJ_DIR/randombytes.o" "$OBJ_DIR/e2ee_proxy_api.o")

# shellcheck disable=SC2086
"$CC" $SHARED_FLAGS -o "$OUT_DIR/$SO_NAME" "${OBJS[@]}" $LDLIBS

if [ "$UNAME" != "Darwin" ]; then
    strip --strip-unneeded "$OUT_DIR/$SO_NAME"
fi

echo "=== built $OUT_DIR/$SO_NAME ==="
ls -la "$OUT_DIR/$SO_NAME"

# Export check: every symbol the Lua cdef needs must be present.
EXPECTED="e2ee_init e2ee_build_info e2ee_get_cert_der e2ee_get_intermediate_der e2ee_get_root_der \
e2ee_get_privkey_der e2ee_mlkem_keygen e2ee_mlkem_encapsulate e2ee_mlkem_decapsulate e2ee_hkdf_sha256 \
e2ee_chacha20_seal e2ee_chacha20_open e2ee_gzip_compress e2ee_gzip_decompress e2ee_random_bytes"
if [ "$UNAME" = "Darwin" ]; then
    SYMS="$(nm -gU "$OUT_DIR/$SO_NAME" | awk '{print $3}' | sed 's/^_//')"
else
    SYMS="$(nm -D --defined-only "$OUT_DIR/$SO_NAME" | awk '{print $3}')"
fi
missing=0
for s in $EXPECTED; do
    if ! grep -qx "$s" <<<"$SYMS"; then
        echo "ERROR: exported symbol missing: $s" >&2
        missing=1
    fi
done
[ "$missing" = 0 ] || exit 1
echo "=== all $(wc -w <<<"$EXPECTED" | tr -d ' ') expected symbols exported ==="

if [ "$RUN_SELFTEST" = 1 ]; then
    echo "=== building self-test ==="
    # Link the self-test statically against the object files (not the .so) so
    # it can reach the deterministic *_derand ML-KEM entry points for KATs.
    # shellcheck disable=SC2086
    "$CC" $CFLAGS $BACKEND_DEFINE $INCLUDES -o "$OUT_DIR/e2ee_selftest" \
        "$SCRIPT_DIR/selftest.c" "${OBJS[@]}" $LDLIBS
    "$OUT_DIR/e2ee_selftest"
fi
