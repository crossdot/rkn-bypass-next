#!/usr/bin/env bash
# P5.2: полевой стенд для реальных сетей РФ.
#
# Прогоняет набор сценариев на удалённый сервер (--host) через реальный mTLS
# (--client-cert/--client-key/--ca) и пишет одну строку CSV на сценарий.
# Использует `scripts/load.sh --remote` (не дублирует его логику) и
# `diag-cli check --json` (парсинг через jq).
#
# НЕ запускается в CI (нужны реальные сим-карты и сети). CI-smoke — только
# `--dry-run`. Прогон — вручную владельцем проекта.
#
# Usage:
#   scripts/field-test.sh --operator MTS --region MSK --access 4g \
#     --device android --host vpn.example.com:443 \
#     --client-cert /path/client.crt --client-key /path/client.key \
#     --ca /path/ca.crt --out results/ [--dry-run]
#
# Опции:
#   --operator     оператор (MTS|Megafon|Beeline|Tele2|Rostelecom|...)  [обяз]
#   --region       регион (MSK, SPB, ...)                              [обяз]
#   --access       4g|5g|wifi|ethernet                                 [обяз]
#   --device       android|ios|laptop|desktop                          [обяз]
#   --host         сервер <host:port> (DIAG_SERVER / SERVER_ADDR)      [обяз]
#   --client-cert  клиентский сертификат (mTLS)                        [обяз]
#   --client-key   клиентский ключ                                     [обяз]
#   --ca           CA-сертификат                                       [обяз]
#   --out          каталог для CSV (`<operator>-<region>-<date>.csv`)  [обяз]
#   --clients      воркеров на load (default 10)
#   --duration     длительность load-сценария, с (default 60)
#   --targets      пробельные URL реальных сайтов для curl (default 3)
#   --diag-target  host:port для diag-этапа socks5 (default ya.ru:443)
#   --dry-run      валидирует аргументы/бинарники и печатает план, выход 0
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${LOAD_BIN:-$ROOT/target/release}"
DIAG_BIN="${DIAG_BIN:-$BIN/diag-cli}"

OPERATOR=""
REGION=""
ACCESS=""
DEVICE=""
HOST=""
CLIENT_CERT=""
CLIENT_KEY=""
CA=""
OUT=""
DRY_RUN=0
CLIENTS=10
DURATION=60
TARGETS="https://ya.ru https://habr.com https://github.com"
DIAG_TARGET="ya.ru:443"

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --operator) OPERATOR="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --access) ACCESS="$2"; shift 2 ;;
    --device) DEVICE="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --client-cert) CLIENT_CERT="$2"; shift 2 ;;
    --client-key) CLIENT_KEY="$2"; shift 2 ;;
    --ca) CA="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --clients) CLIENTS="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --targets) TARGETS="$2"; shift 2 ;;
    --diag-target) DIAG_TARGET="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

fail() { echo "[field-test] $*" >&2; exit 2; }

# ---------- валидация ----------
[ -n "$OPERATOR" ] || fail "--operator is required"
[ -n "$REGION" ] || fail "--region is required"
[ -n "$ACCESS" ] || fail "--access is required (4g|5g|wifi|ethernet)"
[ -n "$DEVICE" ] || fail "--device is required (android|ios|laptop|desktop)"
[ -n "$HOST" ] || fail "--host <server:port> is required"
[ -n "$CLIENT_CERT" ] || fail "--client-cert is required"
[ -n "$CLIENT_KEY" ] || fail "--client-key is required"
[ -n "$CA" ] || fail "--ca is required"
[ -n "$OUT" ] || fail "--out <dir> is required"

case "$ACCESS" in 4g|5g|wifi|ethernet) ;; *) fail "bad --access '$ACCESS'" ;; esac
case "$DEVICE" in android|ios|laptop|desktop) ;; *) fail "bad --device '$DEVICE'" ;; esac

[ -x "$BIN/client" ] || fail "release client not found under $BIN (cargo build --release --workspace)"
[ -x "$DIAG_BIN" ] || fail "release diag-cli not found under $BIN (cargo build --release --workspace)"
for f in "$CLIENT_CERT" "$CLIENT_KEY" "$CA"; do
  [ -f "$f" ] || fail "$f not found"
done

# ---------- --dry-run: печатаем план, ничего не запускаем ----------
if [ "$DRY_RUN" -ne 0 ]; then
  echo "[dry-run] operator=$OPERATOR region=$REGION access=$ACCESS device=$DEVICE"
  echo "[dry-run] host=$HOST diag_target=$DIAG_TARGET clients=$CLIENTS duration=${DURATION}s"
  echo "[dry-run] client-cert=$CLIENT_CERT client-key=$CLIENT_KEY ca=$CA"
  echo "[dry-run] out=$OUT"
  echo "[dry-run] commands:"
  echo "  DIAG_SERVER=$HOST CLIENT_CERT=$CLIENT_CERT CLIENT_KEY=$CLIENT_KEY CA_PATH=$CA $DIAG_BIN check $DIAG_TARGET --transport tls --json"
  echo "  DIAG_SERVER=$HOST ... $DIAG_BIN check $DIAG_TARGET --transport quic --json"
  for t in auto tls quic; do
    echo "  scripts/load.sh --remote $HOST --client-cert ... --client-key ... --ca ... --scenario basic --transport $t --clients $CLIENTS --duration ${DURATION}s --target <site>"
  done
  for site in $TARGETS; do
    echo "  scripts/load.sh --remote $HOST ... --scenario basic --transport tls --clients 1 --duration 5 --target $site (curl check)"
  done
  echo "  -> writes $OUT/<operator>-<region>-<date>.csv"
  echo "[dry-run] OK (nothing launched)"
  exit 0
fi

TS="$(date +%Y-%m-%dT%H:%M:%S)"
DATE="$(date +%F)"
mkdir -p "$OUT"
CSV="$OUT/$OPERATOR-$REGION-$DATE.csv"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ROWS="$TMP/rows.csv"

HEADER="operator,region,access,device,timestamp,scenario,transport,requests,errors,req_s,probe_ok,cached_ok,udp_filtered,tls_refused,server_unreachable,all_failed_default,fallback_prev_failed,transport_selected,p50,p95,p99,diag_connect,diag_handshake,diag_data,diag_socks5,note"

# Набор метаданных для каждой строки.
MD="$OPERATOR,$REGION,$ACCESS,$DEVICE,$TS"

# row <21 поле>: scenario,transport,requests,errors,req_s,probe_ok,cached_ok,
#   udp_filtered,tls_refused,server_unreachable,all_failed_default,
#   fallback_prev_failed,transport_selected,p50,p95,p99,diag_connect,
#   diag_handshake,diag_data,diag_socks5,note.
# Метаданные (operator,region,access,device,timestamp) добавляются автоматически.
row() {
  local csv="$MD"
  local f
  for f in "$@"; do
    csv+=",$f"
  done
  printf '%s\n' "$csv" >>"$ROWS"
}

# sv <summary> <key> — вытащить значение из строки key=value в SUMMARY.
sv() {
  printf '%s\n' "$1" | awk -v k="$2" '{ for(i=1;i<=NF;i++){ if(split($i,a,"=")>1 && a[1]==k){ print a[2]; exit } } }'
}

# diag_stage <json> <name> -> status/class этапа (ok|skipped|<underscore class>).
diag_stage() {
  echo "$1" | jq -r ".stages[] | select(.name==\"$2\") | (.class // .status)" 2>/dev/null || true
}

# ---------- сценарий diag ----------
run_diag() { # transport label
  local t="$1" label="$2" json note=""
  json="$(DIAG_SERVER="$HOST" CLIENT_CERT="$CLIENT_CERT" CLIENT_KEY="$CLIENT_KEY" \
    CA_PATH="$CA" "$DIAG_BIN" check "$DIAG_TARGET" --transport "$t" --json 2>/dev/null || true)"
  local dc dh dd ds
  dc=$(diag_stage "$json" connect); dh=$(diag_stage "$json" handshake)
  dd=$(diag_stage "$json" data); ds=$(diag_stage "$json" socks5)
  [ -z "$dc" ] && [ -z "$dh" ] && [ -z "$dd" ] && [ -z "$ds" ] && note="diag failed to run"
  row "$label" "$t" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "$dc" "$dh" "$dd" "$ds" "$note"
}

# ---------- сценарий load ----------
run_load() { # transport label extra_load_args...
  local t="$1" label="$2" note=""; shift 2
  local sum
  sum="$(bash "$ROOT/scripts/load.sh" --remote "$HOST" \
    --client-cert "$CLIENT_CERT" --client-key "$CLIENT_KEY" --ca "$CA" \
    --scenario basic --transport "$t" --clients "$CLIENTS" --duration "$DURATION" \
    --target "$TARGET" "$@" 2>/dev/null || true)"
  local requests errors req_s probe cached udp tl rej fb fp trs p50 p95 p99
  requests=$(sv "$sum" requests)
  errors=$(sv "$sum" errors)
  req_s=$(sv "$sum" req_s)
  local ts_line
  ts_line=$(printf '%s\n' "$sum" | grep -E '^transport_selected:' || true)
  probe=$(printf '%s\n' "$ts_line" | grep -oE 'probe_ok=[0-9]+' | cut -d= -f2 || true)
  cached=$(printf '%s\n' "$ts_line" | grep -oE 'cached_ok=[0-9]+' | cut -d= -f2 || true)
  udp=$(printf '%s\n' "$ts_line" | grep -oE 'udp_filtered=[0-9]+' | cut -d= -f2 || true)
  tl=$(printf '%s\n' "$ts_line" | grep -oE 'tls_refused=[0-9]+' | cut -d= -f2 || true)
  rej=$(printf '%s\n' "$ts_line" | grep -oE 'server_unreachable=[0-9]+' | cut -d= -f2 || true)
  fb=$(printf '%s\n' "$ts_line" | grep -oE 'all_failed_default=[0-9]+' | cut -d= -f2 || true)
  fp=$(printf '%s\n' "$ts_line" | grep -oE 'fallback_prev_failed=[0-9]+' | cut -d= -f2 || true)
  trs=$(printf '%s\n' "$ts_line" | grep -oE 'transports=[^ ]*' | cut -d= -f2 || true)
  local lat
  lat=$(printf '%s\n' "$sum" | grep -E '^latency_total_s:' || true)
  p50=$(printf '%s\n' "$lat" | grep -oE 'p50=[0-9.]+' | cut -d= -f2 || true)
  p95=$(printf '%s\n' "$lat" | grep -oE 'p95=[0-9.]+' | cut -d= -f2 || true)
  p99=$(printf '%s\n' "$lat" | grep -oE 'p99=[0-9.]+' | cut -d= -f2 || true)
  row "$label" "$t" "$requests" "$errors" "$req_s" "$probe" "$cached" "$udp" "$tl" "$rej" \
    "$fb" "$fp" "$trs" "$p50" "$p95" "$p99" "" "" "" "" "$note"
}

# ---------- сценарий curl (проверка relay на реальных сайтах) ----------
run_curl() { # url
  local url="$1"
  local site; site="$(echo "$url" | sed -E 's#https?://##; s#/.*##')"
  local sum
  sum="$(bash "$ROOT/scripts/load.sh" --remote "$HOST" \
    --client-cert "$CLIENT_CERT" --client-key "$CLIENT_KEY" --ca "$CA" \
    --scenario basic --transport tls --clients 1 --duration 5 \
    --target "$url" 2>/dev/null || true)"
  local requests errors note="$url"
  requests=$(sv "$sum" requests)
  errors=$(sv "$sum" errors)
  row "curl" "tls" "$requests" "$errors" "" "" "" "" "" "" "" "" "tls" "" "" "" "" "" "" "" "$note"
}

# ---------- исполнение ----------
run_diag tls diag_tls
run_diag quic diag_quic
for t in auto tls quic; do
  TARGET="$(echo "$TARGETS" | awk '{print $1}')"   # первый сайт как target load
  run_load "$t" "load_$t"
done
for url in $TARGETS; do
  run_curl "$url"
done

mkdir -p "$(dirname "$CSV")"
{ echo "$HEADER"; cat "$ROWS"; } >"$CSV"

echo "=== P5.2 field test: $OPERATOR / $REGION / $ACCESS ==="
echo "csv=$CSV"
cat "$CSV"
echo "RESULT: OK"
