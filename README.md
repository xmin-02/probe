# PROBE

**Exploit-oriented kernel fuzzer** built on top of Google's [syzkaller](https://github.com/google/syzkaller).

PROBE transforms syzkaller from a general-purpose coverage-guided fuzzer into one that actively hunts for **exploitable** vulnerabilities (UAF, OOB, double-free, privilege escalation) using eBPF runtime monitoring, AI-guided analysis, and adaptive mutation scheduling.

## Key Features

### eBPF Runtime Monitor (Phase 5/7/8a)
- **Slab lifecycle tracking** via tracepoint/kprobe hooks (`kfree`, `kmalloc`, `commit_creds`, `kmem_cache_free`, `_copy_from_user`)
- Real-time detection of: slab reuse, rapid reuse (<100us), double-free, cross-cache reallocation, privilege escalation (uid 0 transition), write-to-freed
- Per-execution **UAF exploitability score** (0-100) fed back to fuzzer
- Zero kernel source modification -- attaches to existing kernel interfaces

### AI-Guided Fuzzing (Phase 3)
- Multi-provider LLM integration (Anthropic Claude / OpenAI)
- Crash exploitability scoring and classification
- Adaptive fuzzing strategy: syscall weight tuning, seed generation, mutation hints
- GPTrace embedding-based crash deduplication
- SyzGPT dependency-aware seed generation
- Web dashboard with cost tracking (USD/KRW)

### Focus Mode (Phase 2)
- High-severity crash triggers intensive mutation (300 iterations vs 25)
- Automatic diminishing-returns exit (50 consecutive no-progress iterations)
- Fault injection integration for error-path UAF discovery
- Concurrency-limited queue with priority scheduling

### Crash Filtering & Dedup (Phase 1)
- 3-tier severity classification (Critical / Important / Stats-only)
- Group-based deduplication preserving variant diversity
- Same crash point with different trigger paths = different exploit potential

### Adaptive Mutation Scheduling (Phase 6)
- **DEzzer**: Hybrid Thompson Sampling + Differential Evolution optimizer
- Per-source coverage tracking (mutate / smash / focus)
- Data-driven mutation operator weight adjustment

## Architecture

```
Host (syz-manager)                Guest VM (QEMU)
+--------------------------+      +----------------------------------+
| Manager                  |      | eBPF Programs (pinned)           |
|  - AI Triage (LLM)      |      |  kfree/kmalloc tracepoints       |
|  - Crash dedup/grouping  |      |  commit_creds kprobe             |
|  - Focus Mode scheduler  |      |  kmem_cache_free kprobe          |
|  - Web dashboard         |      |  _copy_from_user kprobe          |
|  - DEzzer optimizer      |      |  metrics + freed_objects maps    |
+--------------------------+      +----------------------------------+
         |                                    |
         v                                    v
+--------------------------+      +----------------------------------+
| Fuzzer                   |      | syz-executor                     |
|  - Coverage feedback     |      |  Read eBPF metrics per-exec      |
|  - UAF/OOB scoring       |      |  UAF score computation           |
|  - Focus triggering      |      |  FlatBuffers serialization       |
|  - TS weight selection   |      |  Syscall execution               |
+--------------------------+      +----------------------------------+
```

## Requirements

### System
- **OS**: Ubuntu/Debian (tested on Ubuntu 24.04+)
- **Architecture**: x86_64
- **RAM**: 16GB+ recommended (10GB allocated to QEMU VMs)
- **Disk**: 50GB+ free space
- **Virtualization**: KVM support (`/dev/kvm`)

### Software
- GCC, G++, Make, Flex, Bison
- Clang, LLVM, LLD (for eBPF compilation)
- QEMU (`qemu-system-x86`, `qemu-utils`, `qemu-kvm`)
- Go 1.24+ (installed automatically by setup script)
- Python 3 (for rootfs image creation)
- `debootstrap` (for Debian rootfs)
- `libelf-dev`, `libssl-dev`, `libncurses-dev`, `dwarves`

### Optional
- **LLM API key** (Anthropic or OpenAI) for AI-guided fuzzing
- **eBPF**: Requires `CONFIG_BPF=y`, `CONFIG_KPROBES=y` in target kernel

## Quick Start

```bash
# 1. Clone
git clone https://github.com/xmin-02/probe.git
cd probe

# 2. Full automated setup (kernel build + QEMU image + syzkaller + config)
sudo ./build_probe.sh

# 3. Run the fuzzer
cd syzkaller/setup && ./probe.sh
# Or: sudo syzkaller/bin/syz-manager -config syzkaller/setup/probe.cfg
```

The web dashboard is available at `http://127.0.0.1:56741`.

### AI Configuration (Optional)

Add to `syzkaller/setup/probe.cfg`:
```json
{
    "ai_triage": {
        "model": "claude-sonnet-4-5-20250929",
        "api_key": "your-api-key-here"
    }
}
```

Without `ai_triage` config, PROBE runs with all other features enabled -- AI is gracefully disabled.

### Kernel Config Requirements

The target kernel should be built with:
```
CONFIG_KASAN=y              # Kernel Address Sanitizer (UAF/OOB detection)
CONFIG_KASAN_INLINE=y       # Inline instrumentation (faster)
CONFIG_DEBUG_INFO=y          # Debug symbols for crash reports
CONFIG_KCOV=y               # Coverage guidance
CONFIG_BPF=y                # eBPF support
CONFIG_KPROBES=y            # kprobe-based eBPF programs
```

Recommended kernel cmdline (set in `probe.cfg`):
```
kasan_multi_shot panic_on_warn=1 ftrace_dump_on_oops=orig_cpu
```

## Build Commands

```bash
# Go environment (if not using build_probe.sh)
export GOROOT=$PWD/goroot GOPATH=$PWD/gopath PATH=$GOPATH/bin:$GOROOT/bin:$PATH

# Build syzkaller
cd syzkaller
make              # All components
make host         # Host tools only (syz-manager, etc.)
make executor     # Executor only (C++)

# Run tests
make test         # All tests
go test ./pkg/fuzzer/...   # Specific package
```

## Implementation Status

| Phase | Description | Status |
|-------|------------|--------|
| 1 | Crash Filtering & Dedup Pipeline | Done |
| 2 | Focus Mode | Done |
| 3 | AI-Guided Fuzzing (LLM integration) | Done |
| 4 | Practical Hardening (KASAN, fault injection, OOB) | Done |
| 5 | eBPF Runtime Monitor | Done |
| 6 | AI Cost Optimization + Data-Driven Scheduling (DEzzer) | Done |
| 7 | Core Detection Enhancement (CO-RE kprobes) | Done |
| 8a | Write-to-freed eBPF Detection | Done |
| 8b-8f | Mutation & Coverage Innovation | Planned |
| 9-12 | Advanced Coverage, Spec Generation, Concurrency | Planned |

Full technical plan: [`probe.md`](probe.md) (English) / [`probe_kor.md`](probe_kor.md) (Korean)

## Web Dashboard

PROBE extends syzkaller's web interface with:

- **Crash table**: AI exploitability score column (color-coded)
- **`/ai`**: AI dashboard -- analysis summary, cost tracking, real-time console
- **`/ai/triage`**: Crash exploitability analysis, strategy details
- **`/ai/embeddings`**: GPTrace crash dedup clusters
- **`/ai/analytics`**: Cost trends, score distribution charts
- **eBPF stats**: `ebpf reuses`, `ebpf uaf`, `ebpf double-free`, `ebpf cross-cache`, `ebpf write-to-freed`, `ebpf priv-esc`

## Project Structure

```
build_probe.sh              # Automated full-stack setup script
probe.md / probe_kor.md     # Technical plan (EN/KR)
syzkaller/                  # Modified syzkaller (all PROBE changes here)
  executor/
    executor.cc             # Syscall executor + eBPF integration
    ebpf/
      probe_ebpf.bpf.c     # eBPF programs (tracepoint + kprobe)
      probe_ebpf.bpf.h     # Shared metrics structure
  pkg/
    aitriage/               # AI-guided fuzzing (LLM client, prompts)
    fuzzer/
      fuzzer.go             # Fuzzing loop + eBPF feedback
      job.go                # Focus mode, smash, triage jobs
      dezzer.go             # DEzzer TS+DE optimizer
      stats.go              # Dashboard statistics
    flatrpc/                # FlatBuffers RPC (executor <-> manager)
    manager/                # Manager business logic
  tools/
    syz-ebpf-loader/        # BPF loader for VM deployment
  setup/
    probe.cfg               # Fuzzer configuration
```

## Related Research

PROBE integrates techniques from 30+ kernel fuzzing papers:

| Paper | Venue | Technique |
|-------|-------|-----------|
| SyzGPT | ISSTA 2025 | Dependency-based seed generation |
| CountDown | CCS 2024 | Refcount-guided UAF detection |
| GPTrace | ICSE 2026 | LLM embedding crash dedup |
| MobFuzz | NDSS 2022 | Multi-objective optimization |
| SeamFuzz | ICSE 2023 | Per-cluster Thompson Sampling |
| Snowplow | ASPLOS 2025 | ML-guided mutation scheduling |
| KernelGPT | ASPLOS 2025 | LLM syscall spec generation |
| SyzScope | USENIX Sec 2022 | Exploit-oriented crash analysis |

## Constraints

- All modifications are within the `syzkaller/` directory only
- Linux kernel source is never modified (kernel `.config` changes are allowed)
- eBPF programs attach to existing kernel interfaces (tracepoints, kprobes)

## License

Based on [syzkaller](https://github.com/google/syzkaller) (Apache 2.0).
