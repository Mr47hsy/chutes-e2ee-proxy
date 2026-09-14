#!/usr/bin/env bash
#
# Run the pure-Lua unit tests with LuaJIT (no OpenResty needed).
#
#   tests/unit/run.sh              # uses `luajit` from PATH
#   LUAJIT=/path/to/luajit tests/unit/run.sh
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LUAJIT="${LUAJIT:-luajit}"

command -v "$LUAJIT" >/dev/null 2>&1 || { echo "luajit not found (set LUAJIT=...)" >&2; exit 2; }

status=0
for t in "$ROOT"/tests/unit/test_*.lua; do
    echo "== $(basename "$t")"
    if ! "$LUAJIT" -e "package.path='$ROOT/lua/?.lua;$ROOT/tests/unit/?.lua;'..package.path" "$t"; then
        status=1
    fi
done
exit $status
