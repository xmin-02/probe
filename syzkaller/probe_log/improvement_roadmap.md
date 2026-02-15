# PROBE Improvement Roadmap — Research-Backed Enhancement Plan

**Date**: 2026-02-15
**Based on**: Survey of 30+ papers from CCS 2024, NDSS 2024/2025, ASPLOS 2025, USENIX Security 2024, ISSTA 2025, SOSP 2024, ICSE 2026, ATC 2025, and industry reports (Google Project Zero, Anthropic Red Team).

---

## Current System (Phase 1-5 Complete)

| Phase | Component | Status |
|-------|-----------|--------|
| 1 | Crash Filtering & Dedup Pipeline | DONE |
| 2 | Focus Mode | DONE |
| 3 | AI-Guided Fuzzing (Claude Sonnet) | DONE |
| 4 | Practical Hardening (UAF/OOB) | DONE |
| 5 | eBPF Runtime Monitor | DONE |

---

## Enhancement Phases (6-12)

### Phase 6: AI Cost Optimization & Scheduling (Week 1)

**Goal**: 80% API cost reduction + data-driven scheduling replacing fixed heuristics.

| # | Technique | Source | Difficulty | Est. Days | Impact |
|---|-----------|--------|------------|-----------|--------|
| 6a | Batch API migration | Anthropic | ★☆☆ | 0.5 | -50% API cost |
| 6b | Prompt Caching | Anthropic | ★☆☆ | 0.5 | -90% on prefix tokens |
| 6c | Tiered Model Routing (Haiku/Sonnet) | — | ★☆☆ | 0.5 | -60-70% on crash calls |
| 6d | T-Scheduler (Thompson Sampling) | AsiaCCS 2024 | ★☆☆ | 1 | Replace Alternate(2) with MAB |
| 6e | SyzMini (influence-guided minimization) | ATC 2025 | ★★☆ | 2-3 | -60.7% minimization cost, +12.5% coverage |
| 6f | DEzzer (differential evolution scheduling) | IST 2025 | ★☆☆ | 1-2 | Real-time mutation operator optimization |

**Cost projection** (from actual dashboard data, 126 calls / 76 hours):
- Current: $2.19/day (₩3,176)
- After 6a+6b+6c: $0.43/day (₩624) — **80% reduction**

### Phase 7: Core Detection Enhancement (Week 2-3)

**Goal**: Major vulnerability detection improvement via AI seed generation and eBPF extensions.

| # | Technique | Source | Difficulty | Est. Days | Impact |
|---|-----------|--------|------------|-----------|--------|
| 7a | SyzGPT (Dependency RAG for LFS) | ISSTA 2025 | ★★☆ | 3-4 | +323% vuln detection, +17.7% coverage |
| 7b | CountDown (refcount eBPF tracking) | CCS 2024 | ★★☆ | 2-3 | +66.1% UAF detection |
| 7c | Cross-cache precise detection | kmem_cache tracepoint | ★★☆ | 2 | Replaces imprecise size_mismatch |
| 7d | Privilege escalation detection | kprobe on commit_creds | ★☆☆ | 0.5 | Direct exploit detection |
| 7e | GPTrace (embedding-based dedup) | ICSE 2026 | ★★☆ | 2-3 | Better crash grouping accuracy |

**Key metric**: SyzGPT's +323% vulnerability detection is the highest reported gain across all surveyed papers.

### Phase 8: Mutation & Coverage Innovation (Week 3-4)

**Goal**: Smarter mutation strategies and expanded coverage feedback.

| # | Technique | Source | Difficulty | Est. Days | Impact |
|---|-----------|--------|------------|-----------|--------|
| 8a | MOCK (context-aware dependency mutation) | NDSS 2024 | ★★★ | 5-7 | +32% coverage, +15% crashes |
| 8b | SeqFuzz (effective component inference) | Inscrypt 2025 | ★★☆ | 3-4 | +450% bugs, 7.8x speedup |
| 8c | MobFuzz (multi-objective MAB) | NDSS 2024 | ★★☆ | 2-3 | 3x more bugs |
| 8d | SyzAgent coverage feedback in AI prompts | FASE 2025 | ★★☆ | 2 | Better AI strategy accuracy |
| 8e | Write-to-freed detection (copy_from_user) | eBPF kprobe | ★☆☆ | 1 | Strong exploitability signal |

### Phase 9: Advanced Coverage & Detection (Month 2)

**Goal**: Coverage beyond KCOV and page-level/FD-level bug detection.

| # | Technique | Source | Difficulty | Est. Days | Impact |
|---|-----------|--------|------------|-----------|--------|
| 9a | KBinCov (binary-level coverage) | CCS 2024 | ★★★ | 7-10 | +87% binary coverage |
| 9b | Page-level UAF (buddy allocator) | eBPF kprobe | ★★☆ | 2-3 | Dirty Pagetable attack detection |
| 9c | Context-sensitive coverage | bpf_get_stackid | ★★☆ | 3-4 | Different calling contexts |
| 9d | FD lifecycle tracking | eBPF kprobe | ★★☆ | 2 | Double-close, FD reuse |
| 9e | Anamnesis-style exploit assessment | LLM deep analysis | ★★☆ | 2-3 | Accurate exploitability scoring |

### Phase 10: Specification Auto-Generation (Month 2-3)

**Goal**: Expand fuzzing surface by auto-generating syscall specifications.

| # | Technique | Source | Difficulty | Est. Days | Impact |
|---|-----------|--------|------------|-----------|--------|
| 10a | KernelGPT (LLM spec generation) | ASPLOS 2025 | ★★★ | 7-10 | 24 bugs, 11 CVEs |
| 10b | SyzForge (4-stage spec pipeline) | LNCS 2025 | ★★★ | 10-14 | +13.3% coverage, 19 vulns |
| 10c | SyzSpec (symbolic execution specs) | CCS 2025 | ★★★ | 10-14 | 100 crashes |

### Phase 11: Concurrency Bug Detection (Month 3)

**Goal**: New bug class — race conditions and concurrency vulnerabilities.

| # | Technique | Source | Difficulty | Est. Days | Impact |
|---|-----------|--------|------------|-----------|--------|
| 11a | LACE (eBPF sched_ext concurrency) | arXiv 2025 | ★★★ | 7-10 | +38% coverage, 8 new bugs |
| 11b | ACTOR (coverage-directed concurrency) | USENIX Sec 2023 | ★★★ | 7-10 | Systematic race exploration |
| 11c | OZZ (out-of-order memory access) | SOSP 2024 | ★★★ | 10+ | x86 limited, ARM primary |

### Phase 12: Advanced Monitoring & Research (Month 3+)

**Goal**: Specialized exploit pattern detection and experimental techniques.

| # | Technique | Source | Difficulty | Est. Days | Impact |
|---|-----------|--------|------------|-----------|--------|
| 12a | KASLR leak detection | copy_to_user monitoring | ★☆☆ | 1 | Infoleak class |
| 12b | Quarantine bypass detection | KASAN quarantine kprobe | ★★☆ | 2 | Attack pattern detection |
| 12c | Lock ordering monitoring | mutex/spinlock kprobes | ★★★ | 5-7 | Race conditions |
| 12d | CSGO (config-sensitive fuzzing) | ICSE 2026 | ★★★ | 7-10 | +21% coverage |
| 12e | Data-flow coverage proxy | call_site+size tracking | ★★☆ | 2-3 | Lightweight data-flow signal |
| 12f | Snowplow (ML-guided mutation) | ASPLOS 2025 | ★★★ | 14+ | 4.8-5.2x speedup (needs ML infra) |
| 12g | SyzMutateX UCB extraction | DMIT 2025 | ★★☆ | 3-4 | Adaptive mutation energy |
| 12h | Big Sleep tool-augmented analysis | Google P0 | ★★★ | 7-10 | Iterative AI investigation |
| 12i | UAFX (cross-entry UAF analysis) | NDSS 2025 | ★★★ | 10+ | Static analysis integration |
| 12j | SLUBStick pattern detection | USENIX Sec 2024 | ★★☆ | 3 | Timing-based exploit detection |
| 12k | CROSS-X object database | CCS 2025 | ★★☆ | 2-3 | AI triage cache info |
| 12l | KCSAN/KMSAN integration | kernel config | ★☆☆ | 1 | Special kernel builds |

---

## Cost-Incurring vs Free Techniques

### Techniques requiring API costs

| Technique | Cost Type | Additional Cost/Day |
|-----------|-----------|-------------------|
| 7a SyzGPT seed generation | LLM API calls | +$0.10-0.50 |
| 7e GPTrace embedding dedup | Embedding API | +$0.01-0.05 |
| 8d SyzAgent coverage feedback | LLM API calls | +$0.50-2.00 |
| 9e Anamnesis exploit assessment | LLM API calls (deep) | +$0.50-3.00 |
| 10a KernelGPT spec generation | LLM API calls (periodic) | +$0.50-2.00/run |
| 10b SyzForge spec pipeline | LLM API calls | +$0.50-1.00/run |
| 12h Big Sleep tool analysis | LLM API calls (iterative) | +$0.30-1.00 |

### Cost-saving techniques (G category)

| Technique | Savings |
|-----------|---------|
| 6a Batch API | -50% |
| 6b Prompt Caching | -90% on prefix tokens |
| 6c Tiered Model Routing | -60-70% on routine calls |
| Combined (6a+6b+6c) | **-80% total** ($2.19→$0.43/day) |

### Cost projection with all AI features

| Scenario | Daily USD | Daily KRW | Monthly USD | Monthly KRW |
|----------|-----------|-----------|-------------|-------------|
| Current (no changes) | $2.19 | ₩3,176 | $65.70 | ₩95,265 |
| After 6a+6b+6c only | $0.43 | ₩624 | $12.90 | ₩18,705 |
| + All new AI features | $1.05 | ₩1,523 | $31.50 | ₩45,675 |

---

## Research References

### Mutation & Seed Generation
- [SyzGPT](https://github.com/QGrain/SyzGPT) — ISSTA 2025: Dependency-based RAG for low-frequency syscalls
- [MOCK](https://github.com/m0ck1ng/mock) — NDSS 2024: Context-aware syscall dependency mutation
- [Snowplow](https://sishuaigong.github.io/pdf/asplos25-snowplow.pdf) — ASPLOS 2025: ML-guided mutation (Google DeepMind)
- [SeqFuzz](https://link.springer.com/chapter/10.1007/978-981-95-6209-1_16) — Inscrypt 2025: Effective component inference
- [KernelGPT](https://github.com/ise-uiuc/KernelGPT) — ASPLOS 2025: LLM syscall spec generation
- [SyzForge](https://link.springer.com/chapter/10.1007/978-3-031-97620-9_7) — LNCS 2025: Multi-stage spec pipeline
- [SyzSpec](https://www.cs.ucr.edu/~zhiyunq/pub/ccs25_syzspec.pdf) — CCS 2025: Under-constrained symbolic execution
- [SyzMutateX](https://dl.acm.org/doi/10.1145/3736426.3736478) — DMIT 2025: LLM mutation + adaptive energy
- [DEzzer](https://www.sciencedirect.com/science/article/abs/pii/S0164121225004091) — IST 2025: Differential evolution scheduling

### Scheduling & Optimization
- [MobFuzz](https://www.ndss-symposium.org/ndss-paper/mobfuzz/) — NDSS 2024: Multi-objective MAB
- T-Scheduler — AsiaCCS 2024: Thompson Sampling seed scheduling
- [SyzMini](https://github.com/ecnusse/SyzMini) — ATC 2025: Influence-guided minimization

### Coverage
- [KBinCov](http://www.wingtecher.com/themes/WingTecherResearch/assets/papers/paper_from_24/KBinCov_CCS24.pdf) — CCS 2024: Binary-level coverage
- [CSGO](https://conf.researchr.org/details/icse-2026/icse-2026-research-track/94/) — ICSE 2026: Configuration-sensitive fuzzing
- [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/) — NDSS 2024

### UAF & Memory Safety
- [CountDown](https://github.com/psu-security-universe/countdown) — CCS 2024: Refcount-guided UAF fuzzing
- [UAFX](https://github.com/uafx/uafx) — NDSS 2025: Cross-entry UAF static analysis
- [SLUBStick](https://www.usenix.org/conference/usenixsecurity24/presentation/maar-slubstick) — USENIX Sec 2024: Cross-cache attacks
- [CROSS-X](https://kaist-hacking.github.io/pubs/2025/kim:crossx.pdf) — CCS 2025: Generalized cross-cache

### Concurrency
- [LACE](https://arxiv.org/abs/2504.21394) — 2025: eBPF sched_ext concurrency testing
- [ACTOR](https://www.usenix.org/conference/usenixsecurity23/presentation/fleischer) — USENIX Sec 2023
- [OZZ](https://dl.acm.org/doi/10.1145/3694715.3695944) — SOSP 2024: Out-of-order concurrency bugs

### AI/LLM for Security
- [GPTrace](https://arxiv.org/abs/2512.01609) — ICSE 2026: LLM embedding crash dedup
- [SyzAgent](https://arxiv.org/abs/2503.02301) — 2025: Real-time LLM choice table
- [Anamnesis](https://github.com/SeanHeelan/anamnesis-release) — 2026: LLM exploit generation
- [Big Sleep](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html) — Google P0: Tool-augmented AI
- [Anthropic Red Team 0-Days](https://red.anthropic.com/2026/zero-days/) — Claude Opus 4.6: 500+ zero-days

### eBPF & Runtime Monitoring
- [VED-eBPF](https://github.com/hardenedvault/ved-ebpf) — Privilege escalation detection
- [SeaK](https://www.usenix.org/conference/usenixsecurity24/presentation/wang-zicheng) — USENIX Sec 2024: Secure allocator
- [SEV](https://www.usenix.org/conference/osdi24/presentation/sun-hao) — OSDI 2024: eBPF verifier validation
- [Dirty Pagetable](https://sam4k.com/page-table-kernel-exploitation/) — Page-level exploitation

### Surveys
- [SoK: OS Kernel Fuzzing](https://arxiv.org/abs/2501.16165) — 107 papers, 2017-2025
- [SoK: Kernel Exploit Generation](https://www.usenix.org/conference/woot25/presentation/kurmus) — WOOT 2025
