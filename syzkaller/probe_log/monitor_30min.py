#!/usr/bin/env python3
"""Collect fuzzer stats and append to CSV for 30-min monitoring."""
import json, urllib.request, time, os, sys

CSV = "/home/sumin/probe/syzkaller/probe_log/monitor_30min.csv"

def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return json.loads(r.read())
    except:
        return None

def main():
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    fast = fetch("http://127.0.0.1:56741/api/summary")
    kasan = fetch("http://127.0.0.1:56742/api/summary")
    if not fast or not kasan:
        print(f"[{ts}] ERROR: could not fetch stats", file=sys.stderr)
        return
    
    # Write header if new file
    if not os.path.exists(CSV) or os.path.getsize(CSV) == 0:
        with open(CSV, "w") as f:
            f.write("timestamp,fast_corpus,fast_coverage,fast_signal,fast_crashes,fast_crash_types,fast_exec_total,fast_exec_per_sec,fast_uptime,fast_vms,kasan_corpus,kasan_coverage,kasan_signal,kasan_crashes,kasan_crash_types,kasan_exec_total,kasan_exec_per_sec,kasan_uptime,kasan_vms\n")
    
    fast_eps = fast["exec_total"] // max(fast["uptime_sec"], 1)
    kasan_eps = kasan["exec_total"] // max(kasan["uptime_sec"], 1)
    
    with open(CSV, "a") as f:
        f.write(f'{ts},{fast["corpus"]},{fast["coverage"]},{fast["signal"]},{fast["crashes"]},{fast["crash_types"]},{fast["exec_total"]},{fast_eps},{fast["uptime_sec"]},{fast["vms_alive"]}/{fast["vms_total"]},{kasan["corpus"]},{kasan["coverage"]},{kasan["signal"]},{kasan["crashes"]},{kasan["crash_types"]},{kasan["exec_total"]},{kasan_eps},{kasan["uptime_sec"]},{kasan["vms_alive"]}/{kasan["vms_total"]}\n')
    
    print(f"[{ts}] Recorded: fast_cov={fast['coverage']} kasan_cov={kasan['coverage']} fast_eps={fast_eps} crashes={fast['crashes']+kasan['crashes']}")

if __name__ == "__main__":
    main()
