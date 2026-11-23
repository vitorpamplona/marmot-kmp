# shellcheck shell=bash
# Shared plumbing for gen.sh: one loopback relay (`amy serve`), one White Noise
# daemon (B, MDK's wnd) and one amy account (A, marmot-kmp). Nothing leaves
# 127.0.0.0/8. Sourced, not run.
set -uo pipefail

: "${WN_BIN_DIR:?set WN_BIN_DIR to the directory holding the MDK wn and wnd release binaries}"
: "${AMY:?set AMY to the amy launcher (amethyst/cli/build/install/amy/bin/amy)}"
WORK=${WORK:-$(mktemp -d)}
RELAY_HOST=${RELAY_HOST:-127.0.0.2}
RELAY_PORT=${RELAY_PORT:-18790}
RELAY_URL="ws://$RELAY_HOST:$RELAY_PORT"
BLOSSOM_HOST=127.0.0.1
BLOSSOM_PORT=${BLOSSOM_PORT:-18791}
BLOSSOM_URL="http://$BLOSSOM_HOST:$BLOSSOM_PORT"
B_DIR="$WORK/B"
# wnd wants a short (sun_path) socket path in a private directory.
SOCK_DIR=${SOCK_DIR:-$(mktemp -d /tmp/wnavg.XXXXXX)}
B_SOCKET="$SOCK_DIR/b.sock"
A_HOME="$WORK/a-home"
LOG="$WORK/gen.log"
export LC_ALL=C.UTF-8
export WN_ALLOW_LOOPBACK_RELAYS=1 WN_ALLOW_LOOPBACK_BLOB_ENDPOINTS=1 AMY_LOCAL_ONLY=1 AMY_BOOTSTRAP_RELAYS="$RELAY_URL"

log() { printf '[gen] %s\n' "$*" | tee -a "$LOG" >&2; }
die() { log "FAIL: $*"; exit 1; }

wn_b() { "$WN_BIN_DIR/wn" --socket "$B_SOCKET" --json "$@" 2>>"$LOG"; }
amy_a() { HOME="$A_HOME" "$AMY" --account A --secret-backend plaintext --json "$@" 2>>"$LOG"; }

start_relay() {
  local rh="$WORK/relay"
  mkdir -p "$rh"
  HOME="$rh" "$AMY" --account relay --secret-backend plaintext --json init >>"$LOG" 2>&1 || die "relay init"
  nohup env HOME="$rh" "$AMY" --account relay --secret-backend plaintext serve --host "$RELAY_HOST" --port "$RELAY_PORT" \
    >"$rh/out.log" 2>"$rh/err.log" &
  echo $! >"$WORK/relay.pid"
  for _ in $(seq 1 120); do
    curl -s -m 1 -H 'Accept: application/nostr+json' "http://$RELAY_HOST:$RELAY_PORT/" >/dev/null 2>&1 && { log "relay up at $RELAY_URL"; return 0; }
    sleep 0.5
  done
  die "relay never came up"
}

start_blossom() {
  mkdir -p "$WORK/blobs"
  nohup python3 -I "${BLOSSOM_PY:?set BLOSSOM_PY to amethyst/cli/tests/marmot/blossom-server.py}" --host "$BLOSSOM_HOST" --port "$BLOSSOM_PORT" --dir "$WORK/blobs" \
    >"$WORK/blossom.out" 2>"$WORK/blossom.err" &
  echo $! >"$WORK/blossom.pid"
  for _ in $(seq 1 30); do
    grep -q ready "$WORK/blossom.out" 2>/dev/null && { log "blossom up at $BLOSSOM_URL"; return 0; }
    sleep 0.5
  done
  die "blossom never came up"
}

start_wnd() {
  mkdir -p "$B_DIR/logs"; chmod 700 "$B_DIR" "$SOCK_DIR"
  nohup "$WN_BIN_DIR/wnd" --data-dir "$B_DIR" --logs-dir "$B_DIR/logs" --socket "$B_SOCKET" --secret-store file \
    --discovery-relays "$RELAY_URL" --default-account-relays "$RELAY_URL" >"$B_DIR/logs/stdout.log" 2>"$B_DIR/logs/stderr.log" &
  echo $! >"$WORK/wnd.pid"
  for _ in $(seq 1 60); do
    [[ -S "$B_SOCKET" ]] && "$WN_BIN_DIR/wn" --socket "$B_SOCKET" whoami >/dev/null 2>&1 && { log "wnd up"; return 0; }
    sleep 0.5
  done
  die "wnd never came up"
}

stop_all() {
  for p in wnd relay blossom; do
    [[ -f "$WORK/$p.pid" ]] || continue
    kill "$(cat "$WORK/$p.pid")" 2>/dev/null
    rm -f "$WORK/$p.pid"
  done
}
