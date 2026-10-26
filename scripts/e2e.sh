#!/usr/bin/env bash
# End-to-end: apps/server + apps/client (TLS и QUIC) → SOCKS5 → HTTP 200.
# Цель — не-loopback IP контейнера (loopback всегда deny в address rules).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug"
TMP="$(mktemp -d)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

HOST_IP="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
HTTP_PORT=8080
echo "host ip: $HOST_IP, http port: $HTTP_PORT"

# --- client cert + registry ---
CLIENTS_PATH="$TMP/clients.toml" CLIENTS_DIR="$TMP/clients" \
  "$BIN/admin-cli" client add e2e >"$TMP/key.out"
sed -n '/-----BEGIN/,/-----END/p' "$TMP/key.out" >"$TMP/client.key"
CLIENT_CERT="$TMP/clients/e2e.crt"

# --- address rules: allow target IP ---
cat >"$TMP/rules.toml" <<EOF
[server.address_rules]
allow_cidrs = ["$HOST_IP/32"]
EOF

# --- local HTTP server ---
python3 -m http.server "$HTTP_PORT" --bind 0.0.0.0 >"$TMP/http.log" 2>&1 &
PIDS+=($!)
sleep 0.5

run_case() {
  local transport="$1" server_port="$2"
  echo "=== transport=$transport ==="

  TRANSPORT="$transport" LISTEN_ADDR="127.0.0.1:$server_port" \
    CLIENTS_PATH="$TMP/clients.toml" RULES_PATH="$TMP/rules.toml" \
    "$BIN/server" >"$TMP/server-$transport.log" 2>&1 &
  local server_pid=$!
  PIDS+=($server_pid)

  TRANSPORT="$transport" LISTEN_ADDR="127.0.0.1:11080" \
    SERVER_ADDR="127.0.0.1:$server_port" \
    CLIENT_CERT="$CLIENT_CERT" CLIENT_KEY="$TMP/client.key" \
    "$BIN/client" >"$TMP/client-$transport.log" 2>&1 &
  local client_pid=$!
  PIDS+=($client_pid)

  # ждём, пока оба поднимутся
  for _ in $(seq 1 50); do
    if grep -q "listening" "$TMP/server-$transport.log" 2>/dev/null &&
       grep -q "listening" "$TMP/client-$transport.log" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' \
    --socks5 "127.0.0.1:11080" "http://$HOST_IP:$HTTP_PORT/" --max-time 15)"

  kill "$client_pid" "$server_pid" 2>/dev/null || true
  wait "$client_pid" "$server_pid" 2>/dev/null || true

  echo "HTTP code: $code"
  if [[ "$code" != "200" ]]; then
    echo "--- server log ---"; cat "$TMP/server-$transport.log"
    echo "--- client log ---"; cat "$TMP/client-$transport.log"
    return 1
  fi
}

run_case tls 18443
run_case quic 18443
echo "E2E OK (tls + quic)"
