#!/usr/bin/env bash
# Smoke-тест Docker-образов (ADR-011): сборка + docker run + mTLS + сквозная проверка.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

NET="rkn-smoke-net"
SERVER="rkn-server"
CLIENT="rkn-client"
TARGET="rkn-target"
WORK="$(mktemp -d)"
CERTS_DIR="$WORK/certs"
CLIENTS_DIR="$WORK/clients"
RULES_FILE="$WORK/rules.toml"
CLIENTS_FILE="$WORK/clients.toml"

cleanup() {
  docker rm -f "$CLIENT" "$SERVER" "$TARGET" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> building images"
docker build -f deploy/docker/Dockerfile.server-direct -t rkn-server:test .
docker build -f deploy/docker/Dockerfile.client -t rkn-client:test .

# Готовим сертификаты, правила и клиента (admin-cli).
mkdir -p "$CERTS_DIR"
install -m 644 "$ROOT/certs/dev-server.crt" "$CERTS_DIR/server.crt"
install -m 644 "$ROOT/certs/dev-server.key" "$CERTS_DIR/server.key"
install -m 644 "$ROOT/certs/dev-ca.crt" "$CERTS_DIR/ca.crt"
chmod 755 "$CERTS_DIR"

cat > "$RULES_FILE" <<'EOF'
[server.address_rules]
allow_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
EOF
chmod 644 "$RULES_FILE"

echo "==> generating client cert (admin-cli add alice)"
CLIENTS_PATH="$CLIENTS_FILE" CLIENTS_DIR="$CLIENTS_DIR" \
  cargo run -q -p admin-cli -- client add alice > "$WORK/alice.key"

echo "==> creating network"
docker network create "$NET"

echo "==> starting server (mTLS)"
docker run -d --name "$SERVER" --network "$NET" \
  --read-only --cap-drop=ALL --security-opt no-new-privileges --tmpfs /tmp \
  -e RULES_PATH=/etc/netcore/rules.toml \
  -e CLIENTS_PATH=/etc/netcore/clients.toml \
  -v "$RULES_FILE:/etc/netcore/rules.toml:ro" \
  -v "$CLIENTS_FILE:/etc/netcore/clients.toml:ro" \
  -v "$CERTS_DIR:/certs:ro" \
  rkn-server:test

echo "==> starting client (mTLS)"
docker run -d --name "$CLIENT" --network "$NET" \
  --read-only --cap-drop=ALL --security-opt no-new-privileges --tmpfs /tmp \
  -e SERVER_ADDR="$SERVER:8443" \
  -e CLIENT_CERT=/certs/client.crt \
  -e CLIENT_KEY=/certs/client.key \
  -v "$CERTS_DIR/ca.crt:/certs/ca.crt:ro" \
  -v "$CLIENTS_DIR/alice.crt:/certs/client.crt:ro" \
  -v "$WORK/alice.key:/certs/client.key:ro" \
  rkn-client:test

echo "==> starting target (http server)"
docker run -d --name "$TARGET" --network "$NET" \
  python:3-alpine sh -c "python3 -m http.server 8000 --bind 0.0.0.0"

sleep 5

echo "==> smoke 0: no client cert -> TLS rejected"
if docker run --rm --network "$NET" -v "$CERTS_DIR/ca.crt:/ca.crt:ro" curlimages/curl \
    --cacert /ca.crt --max-time 5 -sS "https://$SERVER:8443/" -o /dev/null 2>/dev/null; then
  echo "FAIL: expected mTLS rejection without client cert"
  exit 1
fi
echo "PASS: no client cert rejected"

echo "==> smoke 1: blocked address (127.0.0.1) -> REP 0x02"
OUT="$(docker run --rm --network "$NET" curlimages/curl \
  --socks5 "$CLIENT:1080" --max-time 10 -sS http://127.0.0.1/ 2>&1 || true)"
echo "$OUT"
grep -q "(2)" <<<"$OUT" || { echo "FAIL: expected SOCKS5 reply (2)"; exit 1; }
echo "PASS: blocked address returns 0x02"

echo "==> smoke 2: relay to target -> HTTP 200"
CODE="$(docker run --rm --network "$NET" curlimages/curl \
  --socks5-hostname "$CLIENT:1080" --max-time 10 -sS -o /dev/null -w '%{http_code}' \
  "http://$TARGET:8000/" 2>&1 || true)"
echo "http code: $CODE"
[ "$CODE" = "200" ] || { echo "FAIL: expected HTTP 200, got $CODE"; exit 1; }
echo "PASS: relay returns HTTP 200"

echo "SMOKE OK"
