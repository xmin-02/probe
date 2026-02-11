# PROBE 4-Hour Verification Analysis
**Date**: 2026-02-12, 02:16 ~ 06:20 KST (8 rounds, 30min intervals)
**Fuzzer**: Fresh workdir, 10 VMs, kernel 6.1.20, AI triage enabled

---

## Executive Summary

| Metric | Value | Trend |
|--------|-------|-------|
| Coverage | 62,476 → 114,275 | Steady growth |
| Corpus | 4,586 → 15,201 | Steady growth |
| Exec rate | 506 → 436 /sec | Slight decline (Focus overhead) |
| Crash groups | 1 → 9 | Growing |
| Real UAFs found | 2 | `mas_next_nentry`, `profile_tick` |
| AI cost | $0.68 → $1.03 | Normal |
| Focus triggers | 0 → 67 | **Excessive** |
| eBPF max reuse | 42 → 5,339 | **SATURATING** |
| candidates counter | -10 → -40 | **Bug: going negative** |
| pending counter | 6 → 83 | **Growing unbounded** |

---

## CRITICAL Issues

### Issue #1: eBPF freed_objects Map Saturation (RECURRING)

**Severity**: CRITICAL — defeats the purpose of eBPF scoring
**Status**: Bugfix v5 INSUFFICIENT

**Timeline**:
- 02:20 (Round 1): reuse=1~42 (normal, fix working)
- 02:50 (Round 2): reuse=1~42 (still normal)
- 03:20 (Round 3): reuse=475~587 (saturation beginning!)
- 03:50 (Round 4): reuse=26~34 (some normal values mixed)
- 05:50 (Round 8): reuse=5,338~5,339 (FULLY SATURATED)

**Root Cause**: Bugfix v5 clears only up to 512 entries per `ebpf_read_and_reset()`, but the LRU map has 8192 entries. Each program execution adds many kfree events (potentially hundreds). Over thousands of executions, the 512-entry-per-reset clearing cannot keep up with the inflow, and the map fills again.

**Impact**: Every program gets score=100, Focus mode triggers on EVERYTHING, turning eBPF from a precision tool into pure noise.

**Fix Options**:
1. **Clear ALL entries** (not just 512): Increase the loop limit to 8192, or use a different approach
2. **Zero the metrics map AND delete ALL freed_objects entries** in the child process before `close_fds()`, since we already read metrics there
3. **Replace LRU map with per-CPU array** that is zeroed atomically
4. **Raise the UAF score threshold** from 70 to higher (e.g., 90) to filter noise — but this is a band-aid
5. **Best approach**: Use `BPF_MAP_LOOKUP_AND_DELETE_BATCH` (kernel 5.6+) to clear the entire map in one syscall, or simply increase the per-reset limit to match the map size (8192)

### Issue #2: `candidates` Counter Going Negative

**Severity**: MEDIUM — indicates a counter bug, may affect scheduling
**Status**: New issue discovered

**Timeline**: -10 → -20 → -40 (steadily decreasing by ~10 per hour)

**Likely Cause**: The `InjectSeed()` or `InjectProgram()` from AI strategy is adding to triage candidates, but the counter tracking isn't balanced. Each seed injection decrements the candidates counter without a corresponding increment, or Focus candidate injection is double-counted.

**Impact**: May cause scheduling anomalies. The negative value doesn't crash anything but indicates bookkeeping is wrong.

**Investigation needed**: Check `candidatesBudget` in `fuzzer.go` — the counter might be decremented in `AddFocusCandidate()` or `InjectSeed()` without proper initialization.

### Issue #3: Focus Mode Over-Triggering

**Severity**: HIGH — wastes fuzzing resources on false positives
**Status**: Direct consequence of Issue #1

**Data**: 67 focus triggers in 4 hours = one every ~3.5 minutes. Focus mode is ALWAYS active. Pending queue perpetually at 8 (maximum).

**Effect**: Normal exploration fuzzing is starved. While Focus mode does find new coverage (most sessions report 50-300 new coverage points), the trigger programs are random (every program scores 100), not genuinely UAF-suspicious programs.

**Fix**: Resolving Issue #1 will automatically fix this. Additionally:
- Consider a **cooldown period** between focus sessions (e.g., 5 minutes)
- Add **deduplication by syscall set** (not just title) for focus candidates

### Issue #4: `pending` Counter Growing

**Severity**: LOW — cosmetic/minor scheduling impact
**Status**: New issue discovered

**Timeline**: 6 → 17 → 29 → 48 → 83 (growing ~20/hour)

**Likely Cause**: Related to Issue #2. Focus candidate injection or seed injection increases pending count without proper drain. May also be related to the focus queue always being full (8 pending) generating backpressure.

---

## Positive Findings

### Real Crashes Found (9 groups)

| Crash | Logs | AI Score | Significance |
|-------|------|----------|-------------|
| KASAN: use-after-free Read in mas_next_nentry | 10 | 35 | **Real UAF** — maple tree structure, potential exploit |
| KASAN: use-after-free Read in profile_tick | 1 | 25 | **Real UAF** — timer/profiling, harder to exploit |
| WARNING in collect_domain_accesses | 100 | 15 | Frequent, low exploit potential |
| WARNING in track_pfn_copy | 1 | 15 | Memory management issue |
| WARNING in untrack_pfn | 3 | 15 | Memory management issue |
| WARNING in ext4_rename | 2 | 15 | Filesystem warning |
| suppressed report | 1 | - | Filtered correctly |
| lost connection to test machine | 3 | - | VM instability (normal) |
| SYZFAIL: failed to recv rpc | 4 | - | Internal (normal) |

**Note**: `mas_next_nentry` UAF is the most interesting find. 10 variant logs suggest it's reproducible and worth deeper analysis.

### AI Triage Working Correctly

- 25 API calls total, $1.03 cost (~$6/day rate, within budget)
- 6 crashes analyzed with reasonable scores
- Strategy applied: 10 syscall weights, 5 seeds, 3 focus targets
- Strategy updated at 03:19 and 05:22 (roughly hourly as designed)
- Graceful operation: no errors, no timeouts

### Focus Mode Pending Queue Working

- Queue correctly caps at 8 pending candidates
- Dequeue→launch transitions work correctly
- Focus sessions produce coverage (most 50-300 new coverage points)
- The mechanism itself is correct; the problem is too many triggers from eBPF noise

### Dashboard & Analytics

- Main dashboard: accessible throughout
- /ai page: accessible, cost tracking accurate
- /ai/analytics: accessible throughout
- All pages served correctly for 4+ hours

---

## Performance Trends

```
Time      Corpus   Coverage   Exec/sec   Mode
02:20      4,586    62,476      506     normal
02:50     11,414    95,069      477     FOCUS (ebpf-uaf)
03:20     12,970   103,189      480     FOCUS (ebpf-uaf)
03:50     13,756   107,202      469     FOCUS (ebpf-uaf)
04:20     14,177   109,512      462     FOCUS (ebpf-uaf)
04:50     14,516   111,145      455     FOCUS (ebpf-uaf)
05:20     14,888   112,872      447     FOCUS (ebpf-uaf)
05:50     15,201   114,275      436     FOCUS (ebpf-uaf)
```

**Observations**:
- Coverage growth rate declines over time (expected — diminishing returns in exploration)
- Exec rate slowly declining (~506→436, -14%) — likely due to Focus mode overhead + growing corpus
- Focus mode was active from Round 2 onwards, meaning ~90% of the test was in Focus mode
- Despite Focus dominance, corpus and coverage still grew — Focus does contribute to exploration

---

## Recommended Fixes (Priority Order)

### P0: eBPF freed_objects Full Clearing
**File**: `executor/executor_linux.h`
**Change**: Increase the clearing loop from 512 to 8192 (match map size), or use batch delete
**Estimate**: Simple code change, rebuild executor

### P1: eBPF UAF Score Threshold
**File**: `pkg/fuzzer/fuzzer.go`
**Change**: Raise Focus trigger threshold from score >= 70 to score >= 90 as immediate mitigation
**Reason**: Even with map fix, normal kernel operation produces reuses; higher threshold reduces noise

### P2: Focus Mode Cooldown
**File**: `pkg/fuzzer/fuzzer.go`
**Change**: Add minimum 5-minute gap between focus sessions
**Reason**: Prevents focus-mode monopolizing all resources even if many candidates exist

### P3: candidates Counter Investigation
**File**: `pkg/fuzzer/fuzzer.go`
**Change**: Audit candidatesBudget increments/decrements around InjectSeed and focus paths
**Reason**: Negative counter indicates bookkeeping bug

---

## VM Stability

- VM connection issues: 0 → 3 → 18 over 4 hours
- Some VMs crash due to `panic_on_warn=1` (by design)
- eBPF loader re-deployed on VM restart (working correctly)
- No permanent VM failures observed

---

## Conclusion

The fuzzer is **functionally stable** and finding real crashes (2 UAFs, 4 WARNINGs in 4 hours). AI triage is working correctly with reasonable cost. However, **eBPF scoring saturation** is the dominant issue — it causes Focus mode to run continuously on random programs, reducing the effectiveness of both eBPF scoring and Focus mode.

**Immediate action**: Fix the freed_objects map clearing (increase limit to 8192) and optionally raise the UAF score threshold. This will restore eBPF as a precision tool and make Focus mode target genuinely suspicious programs.
