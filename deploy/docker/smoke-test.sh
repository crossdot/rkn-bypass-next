#!/usr/bin/env bash
# Smoke-тест Docker-образов (ADR-011): сборка + docker run + сквозная проверка.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

NET="rkn-smoke-net"
SERVER="rkn-server"
CLIENT="rkn-client"
TARGET="rkn-target"
CERTS_DIR="$(mktemp -d)"
RULES_FILE="$(mktemp)"

cleanup() {
  docker rm -f "$CLIENT" "$SERVER" "$TARGET" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$CERTS_DIR" "$RULES_FILE"
}
trap cleanup EXIT

echo "==> building images"
docker build -f deploy/docker/Dockerfile.server-direct -t rkn-server:test .
docker build -f deploy/docker/Dockerfile.client -t rkn-client:test .

# Готовим сертификаты и правила с правами, читаемыми non-root UID 10001.
install -m 644 "$ROOT/certs/dev-server.crt" "$CERTS_DIR/server.crt"
install -m 644 "$ROOT/certs/dev-server.key" "$CERTS_DIR/server.key"
install -m 644 "$ROOT/certs/dev-ca.crt" "$CERTS_DIR/ca.crt"
chmod 755 "$CERTS_DIR"
cat > "$RULES_FILE" <<'EOF'
[server.address_rules]
allow_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
EOF
chmod 644 "$RULES_FILE"

echo "==> creating network"
docker network create "$NET"

echo "==> starting server"
docker run -d --name "$SERVER" --network "$NET" \
  --read-only --cap-drop=ALL --security-opt no-new-privileges --tmpfs /tmp \
  -e RULES_PATH=/etc/netcore/rules.toml \
  -v "$RULES_FILE:/etc/netcore/rules.toml:ro" \
  -v "$CERTS_DIR:/certs:ro" \
  rkn-server:test

echo "==> starting client"
docker run -d --name "$CLIENT" --network "$NET" \
  --read-only --cap-drop=ALL --security-opt no-new-privileges --tmpfs /tmp \
  -e SERVER_ADDR="$SERVER:8443" \
  -v "$CERTS_DIR:/certs:ro" \
  rkn-client:test

echo "==> starting target (http server)"
docker run -d --name "$TARGET" --network "$NET" \
  python:3-alpine sh -c "python3 -m http.server 8000 --bind 0.0.0.0"

# Ожидание готовности контейнеров.
sleep 5

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
