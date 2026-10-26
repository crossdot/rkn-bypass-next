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
  local label="$1" server_transport="$2" client_transport="$3" server_port="$4"
  local expect_log="${5:-}"
  local tag="$label"
  echo "=== $label: server=$server_transport client=$client_transport ${CLIENT_ENV:-} ==="

  TRANSPORT="$server_transport" LISTEN_ADDR="127.0.0.1:$server_port" \
    CLIENTS_PATH="$TMP/clients.toml" RULES_PATH="$TMP/rules.toml" \
    "$BIN/server" >"$TMP/server-$tag.log" 2>&1 &
  local server_pid=$!
  PIDS+=($server_pid)

  env TRANSPORT="$client_transport" LISTEN_ADDR="127.0.0.1:11080" \
    SERVER_ADDR="127.0.0.1:$server_port" \
    CLIENT_CERT="$CLIENT_CERT" CLIENT_KEY="$TMP/client.key" \
    ${CLIENT_ENV:-} \
    "$BIN/client" >"$TMP/client-$tag.log" 2>&1 &
  local client_pid=$!
  PIDS+=($client_pid)

  # ждём, пока оба поднимутся; при `auto` сервер печатает два "listening"
  # (TLS-цикл стартует раньше QUIC — иначе проба QUIC может попасть в гонку).
  local want=1
  [[ "$server_transport" == "auto" ]] && want=2
  for _ in $(seq 1 50); do
    if [[ "$(grep -c "listening" "$TMP/server-$tag.log" 2>/dev/null || true)" -ge "$want" ]] &&
       grep -q "listening" "$TMP/client-$tag.log" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' \
    --socks5 "127.0.0.1:11080" "http://$HOST_IP:$HTTP_PORT/" --max-time 20 || true)"

  kill "$client_pid" "$server_pid" 2>/dev/null || true
  wait "$client_pid" "$server_pid" 2>/dev/null || true

  echo "HTTP code: $code"
  if [[ "$code" != "200" ]]; then
    echo "--- server log ---"; cat "$TMP/server-$tag.log"
    echo "--- client log ---"; cat "$TMP/client-$tag.log"
    return 1
  fi
  if [[ -n "$expect_log" ]]; then
    if ! grep -q -- "$expect_log" "$TMP/client-$tag.log"; then
      echo "expected client log to contain: $expect_log"
      echo "--- client log ---"; cat "$TMP/client-$tag.log"
      return 1
    fi
    echo "client log: $(grep -o 'event=transport_selected.*' "$TMP/client-$tag.log" | tail -1)"
  fi
  CLIENT_ENV=""
}

run_case manual-tls tls tls 18443
run_case manual-quic quic quic 18443
# auto на обоих: TLS-first, проба проходит, транспорт = tls.
run_case auto-default auto auto 18443 "event=transport_selected transport=tls reason=probe_ok"
# dual-listen: тот же сервер отвечает по QUIC (ручной выбор транспорта).
run_case dual-listen-manual-quic auto quic 18443
# auto с preferred=quic на dual-listen: QUIC проходит пробу и выбирается.
CLIENT_ENV="TRANSPORT_PREFERRED=quic"
run_case auto-preferred-quic auto auto 18443 "event=transport_selected transport=quic reason=probe_ok"
# UDP недоступен (сервер только TLS), preferred=quic → fallback на TLS с причиной.
CLIENT_ENV="TRANSPORT_PREFERRED=quic TRANSPORT_PROBE_TIMEOUT_MS=1000"
run_case auto-fallback-udp tls auto 18443 "event=transport_selected transport=tls reason=udp_filtered"
echo "E2E OK (manual tls/quic + auto + dual-listen + fallback)"
