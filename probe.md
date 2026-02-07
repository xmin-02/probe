# PROBE — Custom Syzkaller for Exploit-Oriented Kernel Fuzzing

## Scope

- **Modification target**: `syzkaller/` directory ONLY
- **Linux kernel source**: NEVER modified (kernel .config changes are allowed)
- **Goal**: Transform syzkaller from a general-purpose fuzzer into an exploit-oriented fuzzer that focuses on discovering and validating actually exploitable vulnerabilities

## Target Vulnerability Types

- **UAF (Use-After-Free)**: alloc → use → free → reuse patterns
- **OOB (Out-of-Bounds)**: buffer size/offset boundary violations

## Architecture Overview

```
+------------------------------------------------------+
|                PROBE Custom Syzkaller                 |
+------------------------------------------------------+
|                                                       |
|  [Phase 1] Crash Filtering                            |
|    - Impact score based filtering                     |
|    - Prioritize UAF/OOB reports only                  |
|    - Suppress noise (WARNING, LOCKDEP, INFO_LEAK)     |
|                                                       |
|  [Phase 2] Focus Mode                                 |
|    - High-severity crash triggers focused mutation     |
|    - Hundreds~thousands of iterations (not just 25)    |
|    - Crash-type-specific mutation strategies           |
|    - Auto-return on diminishing returns                |
|                                                       |
|  [Phase 3] AI Triage + Focus Guide                    |
|    - LLM-based crash exploitability analysis           |
|    - Mutation strategy suggestions for Focus Mode      |
|    - Post-crash analysis (no hot-loop overhead)        |
|                                                       |
|  [Phase 4] UAF/OOB Mutation Engine                    |
|    - UAF pattern sequence generation                   |
|    - OOB boundary value focused mutation               |
|    - Custom syscall descriptions (uffd, io_uring, etc) |
|                                                       |
|  [Phase 5] eBPF Runtime Monitor                       |
|    - Slab object lifecycle tracking (kprobe-based)     |
|    - Exploitability scoring                            |
|    - Real-time feedback to Focus Mode                  |
|    - No kernel source modification (attach to existing |
|      kprobes/tracepoints)                              |
|                                                       |
+------------------------------------------------------+
```

## Phase 1: Crash Filtering

**Goal**: Eliminate noise, surface only high-severity crashes.

**Current problem**: syzkaller treats all crashes equally — WARNING, LOCKDEP, hangs, and KASAN UAF writes all get the same treatment.

**Modification targets**:
- `pkg/report/crash/` — crash type classification
- `pkg/manager/` — crash storage and reporting logic

**Implementation**:
- Use existing `impactOrder` ranking in `pkg/report/impact_score.go`
- Add filtering layer in manager: only prioritize crashes with high impact scores
- Crash severity tiers:
  - **Tier 1 (Critical)**: KASANInvalidFree, KASANUseAfterFreeWrite, KASANWrite, KASANUseAfterFreeRead, KASANRead
  - **Tier 2 (Important)**: OOB variants, KFENCEInvalidFree, NullPtrDerefBUG
  - **Tier 3 (Low)**: WARNING, LOCKDEP, MemoryLeak, Hang, KCSAN
- Tier 3 crashes stored separately, not triggering Focus Mode

## Phase 2: Focus Mode

**Goal**: When a high-severity crash is found, switch to intensive exploitation of that finding.

**Current behavior**: Crash found → triage → minimize → smash (25 mutations) → move on.

**New behavior**:
```
Normal Mode (exploration)
    |
    +-- Crash detected
          |
          +-- Low severity → Standard processing (25x smash)
          |
          +-- High severity → FOCUS MODE
                |
                +-- 1. Intensive mutation of crash program
                |     +-- Syscall argument micro-variations
                |     +-- Call ordering/timing permutations
                |     +-- Related syscall substitution
                |     +-- UAF: vary free↔reuse gap
                |     +-- OOB: explore size boundaries
                |
                +-- 2. Variant discovery
                |     +-- Upgrade read-UAF → write-UAF
                |     +-- Expand 1-byte OOB → larger OOB
                |     +-- Find different vulns in same code path
                |
                +-- 3. Exit on diminishing returns
                      +-- N consecutive iterations with no new findings
```

**Modification targets**:
- `pkg/fuzzer/job.go` — add `focusJob` type
- `pkg/fuzzer/fuzzer.go` — add `focusQueue` with high priority

**Queue priority** (updated):
```
1. triageCandidateQueue
2. candidateQueue
3. triageQueue
4. focusQueue            ← NEW: high-severity crash intensive mutation
5. smashQueue
6. genFuzz
```

## Phase 3: AI Triage + Focus Guide

**Goal**: Use LLM for crash exploitability analysis and Focus Mode mutation strategy.

**Application points** (no hot-loop overhead):

### 3a. Crash Exploitability Analysis
```
Crash occurs → KASAN report + stack trace sent to LLM
  → "This UAF in nft_set_elem can be exploited via
     same-slab reallocation, privilege escalation possible"
  → Exploitability score + reasoning
  → Informs Focus Mode entry decision
```

### 3b. Focus Mode Strategy
```
Focus Mode entry → crash program + context sent to LLM
  → "To deepen this UAF:
     1. Add ioctl(SET_FLAG) before close()
     2. Try buffer sizes at PAGE_SIZE multiples
     3. Add concurrent read() from another thread"
  → Mutation hints fed to focusJob
```

**Modification targets**:
- New module in `pkg/` or `syz-manager/` for LLM integration
- Focus Mode job to accept external mutation hints

## Phase 4: UAF/OOB Mutation Engine

**Goal**: Add mutation strategies specifically designed to trigger UAF and OOB.

**Modification targets**:
- `prog/mutation.go` — new mutation types + weight adjustments
- `prog/rand.go` — boundary value generation
- `sys/linux/*.txt` — enhanced syscall descriptions

### 4a. UAF-Targeted Mutations
- **Resource lifecycle mutation**: insert free → reuse sequences
  - `open/socket/mmap` → use → `close/munmap` → reuse same fd/ptr
- **Timing mutation**: vary number of calls between free and reuse
- New weight in `MutateOpts`: `UAFPatternWeight`

### 4b. OOB-Targeted Mutations
- **Boundary value injection**: prioritize 0, -1, PAGE_SIZE-1, PAGE_SIZE+1, INT_MAX for size/offset args
- **LenType priority boost**: raise from 1.0 (current) to higher — length fields are key OOB triggers
- **Buffer size mismatch**: deliberately create inconsistency between declared and actual buffer sizes
- Add OOB-specific values to `specialInts` in `prog/rand.go`

### 4c. Enhanced Syscall Descriptions
Focus on interfaces with complex memory management:
- `sys/linux/uffd.txt` (currently 95 lines) — expand with fault-timing patterns
- `sys/linux/io_uring.txt` — add deeper op-specific lifecycle descriptions
- netfilter/nftables object chaining patterns

## Phase 5: eBPF Runtime Monitor

**Goal**: Real-time kernel heap state tracking for exploitability assessment.

**Constraint**: Runs inside Guest VM, attaches to existing kernel functions via kprobes/tracepoints. NO kernel source modification.

### Monitoring targets
- `kprobe/kmalloc`, `kprobe/kfree` — track slab object lifecycle
- `kprobe/copy_from_user`, `kprobe/copy_to_user` — detect OOB access patterns
- slab allocator tracepoints — cache reuse detection

### Feedback loop
```
eBPF detects:
  "Object freed, then same slab cache reallocated 42us later"
  → High exploitability signal
  → Fed back to fuzzer as priority signal

eBPF detects:
  "Write to reallocated object from different context"
  → Critical signal → intensify Focus Mode

eBPF detects:
  "Free without reallocation, read-only access"
  → Low exploitability → deprioritize
```

**Modification targets**:
- New eBPF module (BPF C programs + loader)
- `executor/` — integration with syz-executor in Guest VM
- `pkg/fuzzer/fuzzer.go` — `signalPrio()` extended with eBPF signals

## Implementation Order

| Phase | Component | Difficulty | Impact | Dependencies |
|-------|-----------|-----------|--------|-------------|
| 1 | Crash Filtering | Low | Immediate noise reduction | None |
| 2 | Focus Mode | Medium | Deep exploitation of findings | Phase 1 |
| 3 | AI Triage | Medium | Smart crash analysis | Phase 2 |
| 4 | UAF/OOB Mutations | Medium | Higher vuln discovery rate | None (parallel with 2-3) |
| 5 | eBPF Monitor | High | Real-time exploitability | Phase 2 |

## Key Files Reference

| File | Purpose |
|------|---------|
| `prog/mutation.go` | Mutation strategies & weights |
| `prog/generation.go` | Program generation entry point |
| `prog/rand.go` | Integer generation, special values |
| `pkg/fuzzer/fuzzer.go` | Fuzzing loop, queue management |
| `pkg/fuzzer/job.go` | Job types (triage, smash, hints) |
| `pkg/report/report.go` | Crash parsing pipeline |
| `pkg/report/crash/types.go` | Crash type definitions |
| `pkg/report/impact_score.go` | Severity ranking |
| `pkg/report/linux.go` | Linux-specific crash parsing |
| `pkg/manager/` | Manager business logic |
| `sys/linux/*.txt` | Syscall descriptions (syzlang) |
| `executor/executor.cc` | In-VM syscall executor (C++) |
