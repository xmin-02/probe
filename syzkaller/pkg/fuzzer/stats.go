// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync/atomic"

	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Stats struct {
	// Indexed by prog.Syscall.ID + the last element for extra/remote.
	Syscalls []SyscallStats

	statCandidates          *stat.Val
	statNewInputs           *stat.Val
	statJobs                *stat.Val
	statJobsTriage          *stat.Val
	statJobsTriageCandidate *stat.Val
	statJobsSmash           *stat.Val
	statJobsFocus           *stat.Val // PROBE
	statJobsFaultInjection  *stat.Val
	statJobsHints           *stat.Val
	statExecTime            *stat.Val
	statExecGenerate        *stat.Val
	statExecFuzz            *stat.Val
	statExecCandidate       *stat.Val
	statExecTriage          *stat.Val
	statExecMinimize        *stat.Val
	statExecSmash           *stat.Val
	statExecFocus           *stat.Val // PROBE
	statExecFaultInject     *stat.Val
	statExecHint            *stat.Val
	statExecSeed            *stat.Val
	statExecCollide         *stat.Val
	statCoverOverflows      *stat.Val
	statCompsOverflows      *stat.Val
	statEbpfAllocs          *stat.Val // PROBE: Phase 5
	statEbpfReuses          *stat.Val // PROBE: Phase 5
	statEbpfUafDetected     *stat.Val // PROBE: Phase 5
	statEbpfDoubleFree      *stat.Val // PROBE: Phase 5
	statEbpfSizeMismatch    *stat.Val // PROBE: Phase 5
	statEbpfPrivEsc         *stat.Val // PROBE: Phase 7d
	statEbpfCommitCreds     *stat.Val // PROBE: Phase 7d
	statEbpfCrossCache      *stat.Val // PROBE: Phase 7c
	statEbpfWriteToFreed    *stat.Val // PROBE: Phase 8a
	statEbpfPageAllocs      *stat.Val // PROBE: Phase 9b
	statEbpfPageReuses      *stat.Val // PROBE: Phase 9b
	statEbpfPageUaf         *stat.Val // PROBE: Phase 9b
	statEbpfFdInstalls      *stat.Val // PROBE: Phase 9d
	statEbpfFdCloses        *stat.Val // PROBE: Phase 9d
	statEbpfFdReuse         *stat.Val // PROBE: Phase 9d
	statEbpfContextStacks   *stat.Val // PROBE: Phase 9c
	statEbpfFrees           *stat.Val // PROBE: Phase 5 (H3 fix)
	statEbpfRapidReuse      *stat.Val // PROBE: Phase 5 (H3 fix)
	statEbpfPageFrees       *stat.Val // PROBE: Phase 9b (H3 fix)
	statAnamnesisAssessed   *stat.Val // PROBE: Phase 9e
	statAnamnesisFocused    *stat.Val // PROBE: Phase 9e
	statFocusCovGain        *stat.Val // PROBE: Phase 6 — per-source coverage metrics
	statSmashCovGain        *stat.Val // PROBE: Phase 6
	statFuzzCovGain         *stat.Val // PROBE: Phase 6
	statMutOpSquash         *stat.Val // PROBE: Phase 6 — mutation operator tracking
	statMutOpSplice         *stat.Val // PROBE: Phase 6
	statMutOpInsert         *stat.Val // PROBE: Phase 6
	statMutOpMutateArg      *stat.Val // PROBE: Phase 6
	statMutOpRemove         *stat.Val // PROBE: Phase 6
	statMutOpCovGain        *stat.Val // PROBE: Phase 6
	statSyzGPTGenerated     *stat.Val // PROBE: Phase 7a
	statSyzGPTInjected      *stat.Val // PROBE: Phase 7a
	statDeflakeRuns         *stat.Val // PROBE: Phase 11b
	statDeflakeEarlyExit    *stat.Val // PROBE: Phase 11b
	statCoverageEntropy     *stat.Val // PROBE: Phase 11b
	statSmashDiversity      *stat.Val // PROBE: Phase 11f
	statFocusDropped        *stat.Val // PROBE: Phase 11g
	statFocusBudgetSkip     *stat.Val // PROBE: Phase 11g
	statFocusOptStop        *stat.Val // PROBE: Phase 11g
	statCusumResets         *stat.Val // PROBE: Phase 11a (DEzzer CUSUM)
	statCusumValue          *stat.Val // PROBE: Phase 11a (DEzzer CUSUM)
	statEmaRate             *stat.Val // PROBE: Phase 11a (DEzzer EMA)
	statRaceLockContention  *stat.Val // PROBE: Phase 11i (LACE)
	statRaceConcurrentAccess *stat.Val // PROBE: Phase 11i (LACE)
	statRaceSchedSwitch     *stat.Val // PROBE: Phase 11i (LACE)
	statRaceCandidates      *stat.Val // PROBE: Phase 11i (LACE)
	statRaceThreshold       *stat.Val // PROBE: Phase 11i (LACE)
	statMutOpReorder        *stat.Val // PROBE: Phase 11j (ACTOR reorder op)
	statDelayApplied        *stat.Val // PROBE: Phase 11j (ACTOR delay)
	statDelayNone           *stat.Val // PROBE: Phase 11j (ACTOR delay)
	statDelayRandom         *stat.Val // PROBE: Phase 11j (ACTOR delay)
	statDelayBetween        *stat.Val // PROBE: Phase 11j (ACTOR delay)
	statDelayAroundLocks    *stat.Val // PROBE: Phase 11j (ACTOR delay)
	statLinUCBExploration   *stat.Val // PROBE: Phase 11j (ACTOR LinUCB)
	statSchedYield          *stat.Val // PROBE: Phase 11k (OZZ sched_yield)
	statSchedBoth           *stat.Val // PROBE: Phase 11k (OZZ delay+yield)
	statSchedTSArm          *stat.Val // PROBE: Phase 11k (OZZ current TS arm)
	statBOEpoch             *stat.Val // PROBE: Phase 11l (BO epoch counter)
	statBORate              *stat.Val // PROBE: Phase 11l (BO coverage rate x1000)
	statBORollback          *stat.Val // PROBE: Phase 11l (BO safety rollbacks)
	statPairTSFallback      *stat.Val // PROBE: Phase 12 B4 (pair TS fallback)
}

type SyscallStats struct {
	// Number of times coverage buffer for this syscall has overflowed.
	CoverOverflows atomic.Uint64
	// Number of times comparisons buffer for this syscall has overflowed.
	CompsOverflows atomic.Uint64
}

func newStats(target *prog.Target) Stats {
	return Stats{
		Syscalls: make([]SyscallStats, len(target.Syscalls)+1),
		statCandidates: stat.New("candidates", "Number of candidate programs in triage queue",
			stat.Console, stat.Graph("corpus")),
		statNewInputs: stat.New("new inputs", "Potential untriaged corpus candidates",
			stat.Graph("corpus")),
		statJobs: stat.New("fuzzer jobs", "Total running fuzzer jobs", stat.NoGraph),
		statJobsTriage: stat.New("triage jobs", "Running triage jobs", stat.StackedGraph("jobs"),
			stat.Link("/jobs?type=triage")),
		statJobsTriageCandidate: stat.New("candidate triage jobs", "Running candidate triage jobs",
			stat.StackedGraph("jobs"), stat.Link("/jobs?type=triage")),
		statJobsSmash: stat.New("smash jobs", "Running smash jobs", stat.StackedGraph("jobs"),
			stat.Link("/jobs?type=smash")),
		statJobsFocus: stat.New("focus jobs", "Running focus mode jobs", stat.StackedGraph("jobs"),
			stat.Link("/jobs?type=focus")),
		statJobsFaultInjection: stat.New("fault jobs", "Running fault injection jobs", stat.StackedGraph("jobs")),
		statJobsHints: stat.New("hints jobs", "Running hints jobs", stat.StackedGraph("jobs"),
			stat.Link("/jobs?type=hints")),
		statExecTime: stat.New("prog exec time", "Test program execution time (ms)", stat.Distribution{}),
		statExecGenerate: stat.New("exec gen", "Executions of generated programs", stat.Rate{},
			stat.StackedGraph("exec")),
		statExecFuzz: stat.New("exec fuzz", "Executions of mutated programs",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecCandidate: stat.New("exec candidate", "Executions of candidate programs",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecTriage: stat.New("exec triage", "Executions of corpus triage programs",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecMinimize: stat.New("exec minimize", "Executions of programs during minimization",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecSmash: stat.New("exec smash", "Executions of smashed programs",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecFocus: stat.New("exec focus", "Executions of focus mode programs",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecFaultInject: stat.New("exec inject", "Executions of fault injection",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecHint: stat.New("exec hints", "Executions of programs generated using hints",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecSeed: stat.New("exec seeds", "Executions of programs for hints extraction",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecCollide: stat.New("exec collide", "Executions of programs in collide mode",
			stat.Rate{}, stat.StackedGraph("exec")),
		statCoverOverflows: stat.New("cover overflows", "Number of times the coverage buffer overflowed",
			stat.Rate{}, stat.NoGraph),
		statCompsOverflows: stat.New("comps overflows", "Number of times the comparisons buffer overflowed",
			stat.Rate{}, stat.NoGraph),
		// D10: Split eBPF metrics into logical graph groups (ebpf-uaf, ebpf-heap, ebpf-race).
		statEbpfAllocs: stat.New("ebpf allocs", "Kernel allocs observed by eBPF per execution",
			stat.Rate{}, stat.Graph("ebpf-heap")),
		statEbpfReuses: stat.New("ebpf reuses", "Slab reuses detected by eBPF heap monitor",
			stat.Rate{}, stat.Graph("ebpf-heap")),
		statEbpfUafDetected: stat.New("ebpf uaf", "Non-crashing UAF patterns detected by eBPF",
			stat.Graph("ebpf-uaf")),
		statEbpfDoubleFree: stat.New("ebpf double-free", "Double-free events detected by eBPF",
			stat.Graph("ebpf-heap")),
		statEbpfSizeMismatch: stat.New("ebpf size-mismatch", "Cross-cache size mismatches detected by eBPF",
			stat.Rate{}, stat.Graph("ebpf-heap")),
		statEbpfPrivEsc: stat.New("ebpf priv-esc", "Privilege escalation events detected (uid!=0→uid==0)",
			stat.Graph("ebpf-heap")),
		statEbpfCommitCreds: stat.New("ebpf commit-creds", "commit_creds() calls observed",
			stat.Rate{}, stat.Graph("ebpf-heap")),
		statEbpfCrossCache: stat.New("ebpf cross-cache", "Precise cross-cache reallocation events",
			stat.Graph("ebpf-heap")),
		statEbpfWriteToFreed: stat.New("ebpf write-to-freed", "Writes to freed slab objects via copy_from_user",
			stat.Graph("ebpf-heap")),
		statEbpfPageAllocs: stat.New("ebpf page-allocs", "Page allocations observed by eBPF",
			stat.Rate{}, stat.Graph("ebpf-heap")),
		statEbpfPageReuses: stat.New("ebpf page-reuse", "Page reuse events detected by eBPF",
			stat.Graph("ebpf-heap")),
		statEbpfPageUaf: stat.New("ebpf page-uaf", "Page-level UAF patterns detected",
			stat.Graph("ebpf-uaf")),
		statEbpfFdInstalls: stat.New("ebpf fd-install", "FD installations observed by eBPF",
			stat.Rate{}, stat.Graph("ebpf-race")),
		statEbpfFdCloses: stat.New("ebpf fd-close", "FD closes observed by eBPF",
			stat.Rate{}, stat.Graph("ebpf-race")),
		statEbpfFdReuse: stat.New("ebpf fd-reuse", "FD reuse-after-close patterns detected",
			stat.Graph("ebpf-race")),
		statEbpfContextStacks: stat.New("ebpf ctx-stacks", "Unique context-sensitive stack traces observed",
			stat.Rate{}, stat.Graph("ebpf-race")),
		statEbpfFrees: stat.New("ebpf frees", "Kernel frees observed by eBPF",
			stat.Rate{}, stat.Graph("ebpf-heap")),
		statEbpfRapidReuse: stat.New("ebpf rapid-reuse", "Rapid slab reuse events (alloc within 100us of free)",
			stat.Rate{}, stat.Graph("ebpf-uaf")),
		statEbpfPageFrees: stat.New("ebpf page-frees", "Page frees observed by eBPF",
			stat.Rate{}, stat.Graph("ebpf-heap")),
		statAnamnesisAssessed: stat.New("anamnesis assessed", "Programs assessed by Anamnesis exploit scorer",
			stat.Rate{}, stat.Graph("anamnesis")),
		statAnamnesisFocused: stat.New("anamnesis focused", "Programs sent to Focus by Anamnesis (score>=60)",
			stat.Rate{}, stat.Graph("anamnesis")),
		statFocusCovGain: stat.New("focus cov gain", "Coverage gains from focus mode executions",
			stat.Rate{}, stat.StackedGraph("source cov")),
		statSmashCovGain: stat.New("smash cov gain", "Coverage gains from smash job executions",
			stat.Rate{}, stat.StackedGraph("source cov")),
		statFuzzCovGain: stat.New("fuzz cov gain", "Coverage gains from fuzz/generate executions",
			stat.Rate{}, stat.StackedGraph("source cov")),
		statMutOpSquash: stat.New("mut squash", "Squash operator applications",
			stat.Rate{}, stat.StackedGraph("mut ops")),
		statMutOpSplice: stat.New("mut splice", "Splice operator applications",
			stat.Rate{}, stat.StackedGraph("mut ops")),
		statMutOpInsert: stat.New("mut insert", "Insert operator applications",
			stat.Rate{}, stat.StackedGraph("mut ops")),
		statMutOpMutateArg: stat.New("mut arg", "MutateArg operator applications",
			stat.Rate{}, stat.StackedGraph("mut ops")),
		statMutOpRemove: stat.New("mut remove", "Remove operator applications",
			stat.Rate{}, stat.StackedGraph("mut ops")),
		statMutOpCovGain: stat.New("mut cov gain", "Coverage gains attributed to mutations",
			stat.Rate{}, stat.Graph("mut ops")),
		statSyzGPTGenerated: stat.New("syzgpt gen", "SyzGPT seed programs generated by LLM",
			stat.Graph("syzgpt")),
		statSyzGPTInjected: stat.New("syzgpt inj", "SyzGPT programs validated and injected",
			stat.Graph("syzgpt")),
		statDeflakeRuns: stat.New("deflake runs", "Total deflake re-execution runs",
			stat.Rate{}, stat.NoGraph),
		statDeflakeEarlyExit: stat.New("deflake early", "Deflake early exits (no signal after run 2)",
			stat.Rate{}, stat.NoGraph),
		statCoverageEntropy: stat.New("cov entropy", "Shannon entropy of coverage distribution (x1000)",
			stat.Graph("coverage")),
		statSmashDiversity: stat.New("smash diversity", "Smash iterations using exploration weights",
			stat.Rate{}, stat.NoGraph),
		statFocusDropped: stat.New("focus dropped", "Focus candidates dropped (queue full)",
			stat.Rate{}, stat.Graph("focus")),
		statFocusBudgetSkip: stat.New("focus budget skip", "Focus drains skipped due to 30% budget cap",
			stat.Rate{}, stat.Graph("focus")),
		statFocusOptStop: stat.New("focus opt stop", "Focus jobs stopped by optimal stopping rule",
			stat.Rate{}, stat.Graph("focus")),
		statCusumResets: stat.New("cusum resets", "DEzzer CUSUM change-point resets",
			stat.Rate{}, stat.Graph("dezzer")),
		statCusumValue: stat.New("cusum value", "DEzzer CUSUM statistic (x1000)",
			stat.Graph("dezzer")),
		statEmaRate: stat.New("ema rate", "DEzzer EMA coverage rate (x1000)",
			stat.Graph("dezzer")),
		statRaceLockContention: stat.New("race lock-contention", "Lock contention events detected by LACE",
			stat.Rate{}, stat.Graph("lace")),
		statRaceConcurrentAccess: stat.New("race concurrent-access", "Concurrent access events (sched_switch while lock held)",
			stat.Rate{}, stat.Graph("lace")),
		statRaceSchedSwitch: stat.New("race sched-switch", "Context switches observed by LACE",
			stat.Rate{}, stat.Graph("lace")),
		statRaceCandidates: stat.New("race candidates", "Race condition Focus candidates submitted",
			stat.Graph("lace")),
		statRaceThreshold: stat.New("race threshold", "Current LACE lock contention threshold",
			stat.Graph("lace")),
		statMutOpReorder: stat.New("mut reorder", "Reorder operator applications",
			stat.Rate{}, stat.StackedGraph("mut ops")),
		statDelayApplied: stat.New("delay applied", "Delay injection decisions made by LinUCB",
			stat.Rate{}, stat.Graph("actor")),
		statDelayNone: stat.New("delay none", "Delay pattern: none selected",
			stat.Rate{}, stat.StackedGraph("actor delay")),
		statDelayRandom: stat.New("delay random", "Delay pattern: random delays",
			stat.Rate{}, stat.StackedGraph("actor delay")),
		statDelayBetween: stat.New("delay between", "Delay pattern: uniform between calls",
			stat.Rate{}, stat.StackedGraph("actor delay")),
		statDelayAroundLocks: stat.New("delay locks", "Delay pattern: around lock syscalls",
			stat.Rate{}, stat.StackedGraph("actor delay")),
		statLinUCBExploration: stat.New("linucb explore", "LinUCB exploration vs exploitation ratio",
			stat.Rate{}, stat.Graph("actor")),
		statSchedYield: stat.New("sched yield", "OZZ sched_yield injections",
			stat.Rate{}, stat.StackedGraph("actor delay")),
		statSchedBoth: stat.New("sched both", "OZZ combined delay+yield injections",
			stat.Rate{}, stat.StackedGraph("actor delay")),
		statSchedTSArm: stat.New("sched ts arm", "Current Global TS arm selection",
			stat.Graph("actor")),
		statBOEpoch: stat.New("bo epoch", "Bayesian Optimization epoch number",
			stat.Graph("bo")),
		statBORate: stat.New("bo rate", "BO coverage rate per epoch (x1000)",
			stat.Graph("bo")),
		statBORollback: stat.New("bo rollback", "BO safety rollback events",
			stat.Graph("bo")),
		statPairTSFallback: stat.New("pair ts fallback", "Pair TS fallback due to unknown prevOp",
			stat.Rate{}, stat.Graph("dezzer")),
	}
}
