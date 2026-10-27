#!/usr/bin/env bash
# P11: нагрузочный harness. Запускает server+client, гонит N воркеров через
# SOCKS5 и собирает метрики (латентность curl, ошибки, fd/RSS/tasks).
#
# Usage:
#   scripts/load.sh --clients N --transport tls|quic|auto --duration S \
#                   [--target URL] [--out FILE] [--scenario NAME] \
#                   [--max-sessions M]
#
# Scenarios:
#   basic     — N воркеров, закрытый цикл запросов, p50/p95/p99, fd/RSS/tasks.
#   churn     — быстрый connect/disconnect; проверка, что fd/tasks возвращаются.
#   run_both  — --clients N на КАЖДЫЙ транспорт (TLS+QUIC), сервер auto,
#               глобальный max_sessions (--max-sessions, по умолчанию 750).
#   slow      — медленный target (64KB + sleep), upload через прокси, RSS.
#   abort     — kill клиента mid-transfer; сессии/fd/tasks освобождаются
#               (повторный CONNECT проходит при max_sessions=1).
#   failover  — kill сервера, auto-переход/backoff, recovery после рестарта.
#
# Метрики: curl --write-out '%{http_code} %{time_connect} %{time_total}',
#          /proc/<pid>/fd, ps -o rss=, /proc/<pid>/task,
#          токио alive_tasks (env TASK_METRICS_INTERVAL_S=1).
set -euo pipefail
ulimit -n 65536 2>/dev/null || true

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${LOAD_BIN:-$ROOT/target/release}"

CLIENTS=10
TRANSPORT=auto
DURATION=30
TARGET=""
OUT=""
SCENARIO=basic
MAX_SESSIONS=""
REQ_TIMEOUT="${REQ_TIMEOUT:-30}"

usage() {
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --clients) CLIENTS="$2"; shift 2 ;;
    --transport) TRANSPORT="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --scenario) SCENARIO="$2"; shift 2 ;;
    --max-sessions) MAX_SESSIONS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [ ! -x "$BIN/server" ] || [ ! -x "$BIN/client" ] || [ ! -x "$BIN/admin-cli" ]; then
  echo "release binaries not found under $BIN (run: cargo build --release --workspace)" >&2
  exit 1
fi

TMP="$(mktemp -d)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

HOST_IP="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
HTTP_PORT="${LOAD_HTTP_PORT:-8080}"
SLOW_PORT="${LOAD_SLOW_PORT:-18099}"
SRV_PORT="${LOAD_SRV_PORT:-18443}"
PROXY_PORT="${LOAD_PROXY_PORT:-11080}"
PROXY_PORT_Q="${LOAD_PROXY_PORT_Q:-11081}"

SUMMARY=""
emit() { echo "$*"; SUMMARY+="$*"$'\n'; }
log() { echo "[load] $*" >&2; }

# ---------- cert/registry/rules ----------
CLIENTS_PATH="$TMP/clients.toml"
CLIENTS_DIR="$TMP/clients"
export CLIENTS_PATH CLIENTS_DIR
"$BIN/admin-cli" client add load >"$TMP/key.out"
sed -n '/-----BEGIN/,/-----END/p' "$TMP/key.out" >"$TMP/client.key"
CLIENT_CERT="$TMP/clients/load.crt"

apply_max_sessions() {
  [ -z "$MAX_SESSIONS" ] && return 0
  if grep -q '^max_sessions' "$CLIENTS_PATH"; then
    sed -i "s/^max_sessions = .*/max_sessions = $MAX_SESSIONS/" "$CLIENTS_PATH"
  else
    printf 'max_sessions = %s\n' "$MAX_SESSIONS" >>"$CLIENTS_PATH"
  fi
}
apply_max_sessions

printf '[server.address_rules]\nallow_cidrs = ["%s/32"]\n' "$HOST_IP" >"$TMP/rules.toml"

# ---------- metrics helpers ----------
fd_count() { ls "/proc/$1/fd" 2>/dev/null | wc -l; }
rss_kb() { ps -o rss= -p "$1" 2>/dev/null | tr -d ' ' || true; }
task_count() { ls "/proc/$1/task" 2>/dev/null | wc -l; }
snap() { echo "$(rss_kb "$1") $(fd_count "$1") $(task_count "$1")"; }

sample_start() { # pid outfile
  ( while :; do echo "$(rss_kb "$1") $(fd_count "$1") $(task_count "$1")" >>"$2"; sleep 0.5; done ) &
  echo $! >"$2.pid"
}
sample_stop() { kill "$(cat "$1.pid" 2>/dev/null || true)" 2>/dev/null || true; }
sample_max() { # file -> "rss fd tasks"
  awk '{if($1>r)r=$1; if($2>f)f=$2; if($3>t)t=$3} END{print r+0, f+0, t+0}' "$1" 2>/dev/null || echo "0 0 0"
}

pct() { # file p
  local n; n=$(wc -l <"$1")
  [ "$n" -eq 0 ] && { echo 0; return; }
  local i; i=$(awk -v p="$2" -v n="$n" 'BEGIN{k=int((p/100)*n); if(k<1)k=1; if(k>n)k=n; print k}')
  sort -n "$1" | sed -n "${i}p"
}
mean() { awk '{s+=$1; c++} END{if(c) printf "%.4f", s/c; else print 0}' "$1" 2>/dev/null || echo 0; }

aggregate() { # logdir duration label
  local dir="$1" dur="$2" label="$3"
  local all="$TMP/all-$label.txt"; cat "$dir"/w*.log >"$all" 2>/dev/null || true
  local n err; n=$(wc -l <"$all"); err=$(awk '$1!="200"{c++} END{print c+0}' "$all")
  awk '{print $3}' "$all" >"$TMP/tt-$label"; awk '{print $2}' "$all" >"$TMP/tc-$label"
  local tt50 tt95 tt99 tt_m tc50 tc95 tc99 tc_m rps
  tt50=$(pct "$TMP/tt-$label" 50); tt95=$(pct "$TMP/tt-$label" 95); tt99=$(pct "$TMP/tt-$label" 99)
  tt_m=$(mean "$TMP/tt-$label")
  tc50=$(pct "$TMP/tc-$label" 50); tc95=$(pct "$TMP/tc-$label" 95); tc99=$(pct "$TMP/tc-$label" 99)
  tc_m=$(mean "$TMP/tc-$label")
  rps=$(awk -v n="$n" -v d="$dur" 'BEGIN{if(d>0) printf "%.1f", n/d; else print 0}')
  emit "== $label =="
  emit "requests=$n errors=$err req_s=$rps"
  emit "latency_total_s: p50=$tt50 p95=$tt95 p99=$tt99 mean=$tt_m"
  emit "latency_connect_s: p50=$tc50 p95=$tc95 p99=$tc99 mean=$tc_m"
  AGG_ERRORS=$err
  AGG_REQUESTS=$n
}

report_transport_selected() { # client log
  local logf="$1"
  local total manual probe cached
  total=$(grep -c "event=transport_selected" "$logf" 2>/dev/null || true)
  manual=$(grep -o "reason=manual" "$logf" 2>/dev/null | wc -l || true)
  probe=$(grep -o "reason=probe_ok" "$logf" 2>/dev/null | wc -l || true)
  cached=$(grep -o "reason=cached_ok" "$logf" 2>/dev/null | wc -l || true)
  emit "transport_selected: total=${total:-0} manual=$manual probe_ok=$probe cached_ok=$cached"
}

report_tasks() { # pid log file
  local pid="$1" logf="$2"
  local mx
  mx=$(grep -o "event=task_metrics alive_tasks=[0-9]*" "$logf" 2>/dev/null | sed 's/.*=//' | sort -n | tail -1 || true)
  emit "tokio_alive_tasks_max=${mx:-0} (pid $pid)"
}

leak_check() { # label before "rss fd tasks" after "rss fd tasks"
  local label="$1" b="$2" a="$3"
  local br bf bt ar af at
  read -r br bf bt <<<"$b"; read -r ar af at <<<"$a"
  emit "$label: fd ${bf}->${af}, tasks ${bt}->${at}, rss ${br}->${ar} kB"
  local fd_grow=$((af - bf)) task_grow=$((at - bt))
  if [ "$fd_grow" -gt 8 ] || [ "$task_grow" -gt 4 ]; then
    emit "$label: LEAK (fd+$fd_grow tasks+$task_grow > slack 8)"
    LEAK=1
  fi
}
LEAK=0

# ---------- process orchestration ----------
SERVER_LOG=""; CLIENT_LOG=""; SERVER_PID=""; CLIENT_PID=""

start_server() { # transport
  SERVER_LOG="$TMP/server.log"
  TRANSPORT="$1" LISTEN_ADDR="127.0.0.1:$SRV_PORT" \
    CLIENTS_PATH="$CLIENTS_PATH" RULES_PATH="$TMP/rules.toml" \
    TASK_METRICS_INTERVAL_S=1 RUST_LOG="${RUST_LOG:-info}" \
    "$BIN/server" >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!; PIDS+=("$SERVER_PID")
}
start_client() { # transport proxy_port
  CLIENT_LOG="$TMP/client-$2.log"
  TRANSPORT="$1" LISTEN_ADDR="127.0.0.1:$2" SERVER_ADDR="127.0.0.1:$SRV_PORT" \
    CLIENT_CERT="$CLIENT_CERT" CLIENT_KEY="$TMP/client.key" \
    TASK_METRICS_INTERVAL_S=1 RUST_LOG="${RUST_LOG:-info}" \
    "$BIN/client" >"$CLIENT_LOG" 2>&1 &
  CLIENT_PID=$!; PIDS+=("$CLIENT_PID")
}

wait_ready() { # want_listenings
  local want="$1"
  for _ in $(seq 1 100); do
    local n
    n=$(grep -c listening "$SERVER_LOG" 2>/dev/null || true)
    n=${n:-0}
    if [ "$n" -ge "$want" ] && grep -q listening "$CLIENT_LOG" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

start_http_target() {
  # High-concurrency 200-таргет (ThreadingHTTPServer, backlog 2048), чтобы
  # N=500 не упирался в очередь accept'а целевого сервера.
  cat >"$TMP/http_target.py" <<'PY'
import http.server, socketserver, sys
port = int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 2048
S(("0.0.0.0", port), H).serve_forever()
PY
  python3 "$TMP/http_target.py" "$HTTP_PORT" >"$TMP/http.log" 2>&1 &
  PIDS+=($!)
  sleep 0.6
}

wait_drain() { # pid baseline_fd max_s
  local pid="$1" base="$2" maxs="$3" i=0
  while [ "$i" -lt $((maxs * 4)) ]; do
    local cur; cur=$(fd_count "$pid")
    [ "$cur" -le $((base + 4)) ] && return 0
    sleep 0.25; i=$((i + 1))
  done
  return 1
}

write_slow_target() {
  cat >"$TMP/slow_target.py" <<'PY'
import socket, sys, time
host, port, ms = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port)); s.listen(128)
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    total = 0
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            total += len(d)
            time.sleep(ms / 1000.0)
    except OSError:
        pass
    try:
        c.close()
    except OSError:
        pass
    print(f"slow_target recv total={total}", flush=True)
PY
}
start_slow_target() { # sleep_ms
  python3 "$TMP/slow_target.py" "$HOST_IP" "$SLOW_PORT" "${1:-20}" >"$TMP/slow.log" 2>&1 &
  PIDS+=($!)
  sleep 0.3
}

# ---------- workers ----------
write_worker() {
  cat >"$TMP/worker.sh" <<'SH'
#!/usr/bin/env bash
w="$1"
WLOG="$WLOG_DIR/w$w.log"
while [ $(( START_NS - $(date +%s%N) )) -gt 50000000 ]; do sleep 0.02; done
while [ "$(date +%s%N)" -lt "$START_NS" ]; do :; done
while :; do
  [ "$(date +%s%N)" -ge "$END_NS" ] && break
  curl -s -o /dev/null --socks5-hostname "127.0.0.1:$PROXY" --max-time "$REQ_TIMEOUT" \
    -w "%{http_code} %{time_connect} %{time_total}\n" "$TGT_URL" >>"$WLOG" 2>/dev/null || true
done
SH
  chmod +x "$TMP/worker.sh"
}

run_workers() { # n proxy dur tag target
  local n="$1" proxy="$2" dur="$3" tag="$4" tgt="$5"
  local dir="$TMP/wlogs-$tag"; mkdir -p "$dir"
  local start; start=$(( $(date +%s%N) + 2000000000 ))
  export START_NS="$start" END_NS=$(( start + dur * 1000000000 ))
  export PROXY="$proxy" TGT_URL="$tgt" WLOG_DIR="$dir" REQ_TIMEOUT
  seq 1 "$n" | xargs -P "$n" -n1 bash "$TMP/worker.sh" || true
}

# ---------- scenarios ----------
scenario_basic() {
  start_http_target
  local tgt="${TARGET:-http://$HOST_IP:$HTTP_PORT/}"
  start_server "$TRANSPORT"
  local want=1; [ "$TRANSPORT" = auto ] && want=2
  start_client "$TRANSPORT" "$PROXY_PORT"
  wait_ready "$want" || { log "server/client not ready"; tail -n 5 "$SERVER_LOG" || true; tail -n 5 "$CLIENT_LOG" || true; exit 1; }

  local before before_cli; before=$(snap "$SERVER_PID"); before_cli=$(snap "$CLIENT_PID")
  sample_start "$SERVER_PID" "$TMP/sample-srv"; sample_start "$CLIENT_PID" "$TMP/sample-cli"
  run_workers "$CLIENTS" "$PROXY_PORT" "$DURATION" basic "$tgt"
  sample_stop "$TMP/sample-srv"; sample_stop "$TMP/sample-cli"

  aggregate "$TMP/wlogs-basic" "$DURATION" "basic transport=$TRANSPORT clients=$CLIENTS"
  report_transport_selected "$CLIENT_LOG"
  report_tasks "$SERVER_PID" "$SERVER_LOG"
  read -r smax sfmax stmax <<<"$(sample_max "$TMP/sample-srv")"
  emit "server_during_max: rss=${smax}kB fd=$sfmax tasks=$stmax"
  read -r cmax cfmax ctmax <<<"$(sample_max "$TMP/sample-cli")"
  emit "client_during_max: rss=${cmax}kB fd=$cfmax tasks=$ctmax"
  local bfd bfd_cli
  bfd=$(awk '{print $2}' <<<"$before"); bfd_cli=$(awk '{print $2}' <<<"$before_cli")
  wait_drain "$SERVER_PID" "$bfd" 20 || true
  wait_drain "$CLIENT_PID" "$bfd_cli" 10 || true
  leak_check "server" "$before" "$(snap "$SERVER_PID")"
  leak_check "client" "$before_cli" "$(snap "$CLIENT_PID")"
}

scenario_churn() {
  # Много коротких соединений: тот же basic, но после — проверяем возврат fd/tasks.
  start_http_target
  local tgt="${TARGET:-http://$HOST_IP:$HTTP_PORT/}"
  start_server "$TRANSPORT"
  local want=1; [ "$TRANSPORT" = auto ] && want=2
  start_client "$TRANSPORT" "$PROXY_PORT"
  wait_ready "$want" || { log "not ready"; exit 1; }
  local before; before=$(snap "$CLIENT_PID")
  REQ_TIMEOUT=10 run_workers "$CLIENTS" "$PROXY_PORT" "$DURATION" churn "$tgt"
  aggregate "$TMP/wlogs-churn" "$DURATION" "churn transport=$TRANSPORT clients=$CLIENTS"
  report_transport_selected "$CLIENT_LOG"
  wait_drain "$CLIENT_PID" "$(awk '{print $2}' <<<"$before")" 10 || true
  leak_check "client" "$before" "$(snap "$CLIENT_PID")"
}

scenario_run_both() {
  [ -z "$MAX_SESSIONS" ] && MAX_SESSIONS=750
  apply_max_sessions
  start_http_target
  local tgt="${TARGET:-http://$HOST_IP:$HTTP_PORT/}"
  start_server auto
  start_client tls "$PROXY_PORT"
  wait_ready 2 || { log "server not ready"; exit 1; }
  local cli_tls_log="$CLIENT_LOG"
  start_client quic "$PROXY_PORT_Q"
  for _ in $(seq 1 50); do grep -q listening "$CLIENT_LOG" 2>/dev/null && break; sleep 0.1; done
  local cli_quic_log="$CLIENT_LOG"

  local before; before=$(snap "$SERVER_PID")
  sample_start "$SERVER_PID" "$TMP/sample-srv"
  local half=$(( CLIENTS / 2 )); [ "$half" -lt 1 ] && half=1
  run_workers "$half" "$PROXY_PORT" "$DURATION" both-tls "$tgt" &
  local w1=$!
  run_workers "$half" "$PROXY_PORT_Q" "$DURATION" both-quic "$tgt" &
  local w2=$!
  wait "$w1" "$w2" || true
  sample_stop "$TMP/sample-srv"

  aggregate "$TMP/wlogs-both-tls" "$DURATION" "run_both tls clients=$half"
  report_transport_selected "$cli_tls_log"
  aggregate "$TMP/wlogs-both-quic" "$DURATION" "run_both quic clients=$half"
  report_transport_selected "$cli_quic_log"
  report_tasks "$SERVER_PID" "$SERVER_LOG"
  read -r smax sfmax stmax <<<"$(sample_max "$TMP/sample-srv")"
  emit "server_during_max: rss=${smax}kB fd=$sfmax tasks=$stmax (max_sessions=$MAX_SESSIONS)"
  emit "server_session_limit_events=$(grep -c 'session limit reached' "$SERVER_LOG" 2>/dev/null || true)"
  wait_drain "$SERVER_PID" "$(awk '{print $2}' <<<"$before")" 30 || true
  leak_check "server" "$before" "$(snap "$SERVER_PID")"
}

scenario_slow() {
  write_slow_target
  start_slow_target 20
  start_server "$TRANSPORT"
  local want=1; [ "$TRANSPORT" = auto ] && want=2
  start_client "$TRANSPORT" "$PROXY_PORT"
  wait_ready "$want" || { log "not ready"; exit 1; }
  # 20 MB тело для upload.
  head -c 20M /dev/zero >"$TMP/body.bin"
  local before; before=$(snap "$SERVER_PID")
  sample_start "$SERVER_PID" "$TMP/sample-srv"
  local t0; t0=$(date +%s)
  curl -s -o /dev/null --socks5-hostname "127.0.0.1:$PROXY_PORT" --max-time 20 \
    --data-binary "@$TMP/body.bin" "http://$HOST_IP:$SLOW_PORT/" || true
  local elapsed=$(( $(date +%s) - t0 ))
  sample_stop "$TMP/sample-srv"
  read -r smax sfmax stmax <<<"$(sample_max "$TMP/sample-srv")"
  emit "slow: upload=20MB elapsed=${elapsed}s target=[$(tail -1 "$TMP/slow.log" 2>/dev/null || true)]"
  emit "slow: server_during_max rss=${smax}kB fd=$sfmax tasks=$stmax"
  sleep 1
  leak_check "server" "$before" "$(snap "$SERVER_PID")"
}

scenario_abort() {
  MAX_SESSIONS=1; apply_max_sessions
  write_slow_target
  start_http_target
  start_slow_target 50
  start_server "$TRANSPORT"
  local want=1; [ "$TRANSPORT" = auto ] && want=2
  start_client "$TRANSPORT" "$PROXY_PORT"
  wait_ready "$want" || { log "not ready"; exit 1; }
  head -c 100M /dev/zero >"$TMP/body.bin"
  # Держим единственную сессию долгим upload'ом.
  curl -s -o /dev/null --socks5-hostname "127.0.0.1:$PROXY_PORT" --max-time 60 \
    --data-binary "@$TMP/body.bin" "http://$HOST_IP:$SLOW_PORT/" &
  local upid=$!
  sleep 2
  local before_kill; before_kill=$(snap "$SERVER_PID")
  # Убиваем клиента mid-transfer.
  kill -9 "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  kill "$upid" 2>/dev/null || true
  wait "$upid" 2>/dev/null || true
  sleep 3
  local after_kill; after_kill=$(snap "$SERVER_PID")
  emit "abort: server before_kill(rss fd tasks)=$before_kill after_kill=$after_kill"
  leak_check "server-after-abort" "$before_kill" "$after_kill"
  # max_sessions=1: если сессия освободилась, новый клиент пройдёт (HTTP 200).
  start_client "$TRANSPORT" "$PROXY_PORT"
  for _ in $(seq 1 50); do grep -q listening "$CLIENT_LOG" 2>/dev/null && break; sleep 0.1; done
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --socks5-hostname "127.0.0.1:$PROXY_PORT" \
    --max-time 10 "http://$HOST_IP:$HTTP_PORT/" || true)
  emit "abort: re-admit code=$code (ожидаем 200 при освобождённой сессии)"
  emit "abort: session_limit_events=$(grep -c 'session limit reached' "$SERVER_LOG" 2>/dev/null || true)"
  [ "$code" = "200" ] || LEAK=1
}

scenario_failover() {
  start_http_target
  local tgt="${TARGET:-http://$HOST_IP:$HTTP_PORT/}"
  start_server auto
  start_client auto "$PROXY_PORT"
  wait_ready 2 || { log "not ready"; exit 1; }
  local code; code=$(curl -s -o /dev/null -w '%{http_code}' --socks5-hostname "127.0.0.1:$PROXY_PORT" --max-time 10 "$tgt" || true)
  emit "failover: initial code=$code"
  kill -9 "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true
  local t_fail=""; local now0; now0=$(date +%s)
  while [ $(( $(date +%s) - now0 )) -lt 15 ]; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --socks5-hostname "127.0.0.1:$PROXY_PORT" --max-time 5 "$tgt" || true)
    if [ "$code" != "200" ]; then t_fail=$(( $(date +%s) - now0 )); break; fi
    sleep 0.5
  done
  emit "failover: failure observed after ${t_fail:-?}s (server down)"
  # Держим сервер выключенным DOWN_HOLD секунд — клиент уходит в backoff.
  local down_hold="${FAILOVER_DOWN:-5}"
  local td; td=$(date +%s)
  while [ $(( $(date +%s) - td )) -lt "$down_hold" ]; do
    curl -s -o /dev/null --socks5-hostname "127.0.0.1:$PROXY_PORT" --max-time 3 "$tgt" >/dev/null 2>&1 || true
    sleep 0.5
  done
  emit "failover: down_hold=${down_hold}s; client reasons: all_failed_default=$(grep -o 'reason=all_failed_default' "$CLIENT_LOG" 2>/dev/null | wc -l || true) fallback_prev_failed=$(grep -o 'reason=fallback_prev_failed' "$CLIENT_LOG" 2>/dev/null | wc -l || true)"
  # Рестарт сервера (bind может упереться в TIME_WAIT — пробуем несколько раз).
  local started=0
  for _ in $(seq 1 10); do
    start_server auto
    local ok=0
    for _ in $(seq 1 30); do
      if grep -q listening "$SERVER_LOG" 2>/dev/null; then ok=1; break; fi
      kill -0 "$SERVER_PID" 2>/dev/null || break
      sleep 0.1
    done
    if [ "$ok" -eq 1 ]; then started=1; break; fi
    kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true
    sleep 1
  done
  if [ "$started" -ne 1 ]; then emit "failover: server restart FAILED"; LEAK=1; return; fi
  local t0; t0=$(date +%s)
  local recovered=""
  while [ $(( $(date +%s) - t0 )) -lt 40 ]; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --socks5-hostname "127.0.0.1:$PROXY_PORT" --max-time 5 "$tgt" || true)
    if [ "$code" = "200" ]; then recovered=$(( $(date +%s) - t0 )); break; fi
    sleep 0.5
  done
  emit "failover: recovery after ${recovered:-none}s (ожидаем <=30)"
  if [ -z "$recovered" ] || [ "$recovered" -gt 30 ]; then
    emit "failover: RECOVERY FAILED/SLOW"; LEAK=1
  fi
}

# ---------- main ----------
write_worker
log "scenario=$SCENARIO clients=$CLIENTS transport=$TRANSPORT duration=${DURATION}s host=$HOST_IP"

case "$SCENARIO" in
  basic) scenario_basic ;;
  churn) scenario_churn ;;
  run_both) scenario_run_both ;;
  slow) scenario_slow ;;
  abort) scenario_abort ;;
  failover) scenario_failover ;;
  *) echo "unknown scenario: $SCENARIO" >&2; exit 2 ;;
esac

if [ -n "$OUT" ]; then mkdir -p "$(dirname "$OUT")"; printf '%s' "$SUMMARY" >"$OUT"; fi
if [ "$LEAK" -ne 0 ]; then echo "RESULT: FAIL (leak/recovery)" >&2; exit 1; fi
echo "RESULT: OK"
