#!/bin/bash
# Hourly monitor — runs at top of each hour, appends to hourly_monitor.csv
LOG_CSV="/home/sumin/probe/syzkaller/probe_log/hourly_monitor.csv"

# Write header if new file
if [ ! -f "$LOG_CSV" ]; then
    echo "timestamp,fast_cov,fast_corpus,fast_exec,fast_exec_sec,fast_crashes,fast_crash_types,kasan_cov,kasan_corpus,kasan_exec,kasan_exec_sec,kasan_crashes,kasan_crash_types,uptime_sec" > "$LOG_CSV"
fi

while true; do
    # Sleep until next top of hour
    NOW=$(date +%s)
    NEXT_HOUR=$(( (NOW / 3600 + 1) * 3600 ))
    SLEEP_SEC=$((NEXT_HOUR - NOW))
    sleep "$SLEEP_SEC"

    TS=$(date '+%Y-%m-%d %H:%M:%S')

    FAST=$(curl -s http://127.0.0.1:56741/api/summary 2>/dev/null)
    KASAN=$(curl -s http://127.0.0.1:56742/api/summary 2>/dev/null)

    F_COV=$(echo "$FAST" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('coverage',0))" 2>/dev/null)
    F_CORP=$(echo "$FAST" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('corpus',0))" 2>/dev/null)
    F_EXEC=$(echo "$FAST" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('exec_total',0))" 2>/dev/null)
    F_EPS=$(echo "$FAST" | python3 -c "import json,sys; d=json.load(sys.stdin); print(round(d.get('exec_total',0)/max(d.get('uptime_sec',1),1)))" 2>/dev/null)
    F_CRASHES=$(echo "$FAST" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('crashes',0))" 2>/dev/null)
    F_CT=$(echo "$FAST" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('crash_types',0))" 2>/dev/null)

    K_COV=$(echo "$KASAN" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('coverage',0))" 2>/dev/null)
    K_CORP=$(echo "$KASAN" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('corpus',0))" 2>/dev/null)
    K_EXEC=$(echo "$KASAN" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('exec_total',0))" 2>/dev/null)
    K_EPS=$(echo "$KASAN" | python3 -c "import json,sys; d=json.load(sys.stdin); print(round(d.get('exec_total',0)/max(d.get('uptime_sec',1),1)))" 2>/dev/null)
    K_CRASHES=$(echo "$KASAN" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('crashes',0))" 2>/dev/null)
    K_CT=$(echo "$KASAN" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('crash_types',0))" 2>/dev/null)
    UPTIME=$(echo "$FAST" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('uptime_sec',0))" 2>/dev/null)

    echo "$TS,$F_COV,$F_CORP,$F_EXEC,$F_EPS,$F_CRASHES,$F_CT,$K_COV,$K_CORP,$K_EXEC,$K_EPS,$K_CRASHES,$K_CT,$UPTIME" >> "$LOG_CSV"
    echo "[$TS] Logged: fast_cov=$F_COV fast_eps=$F_EPS/s fast_ct=$F_CT | kasan_cov=$K_COV kasan_ct=$K_CT"
done
