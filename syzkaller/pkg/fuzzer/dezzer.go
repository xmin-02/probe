// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 6 — DEzzer: Hybrid Thompson Sampling + Differential Evolution optimizer
// for mutation operator weights.
//
// Architecture (4-Layer):
//   Final Weight = Default × AI Base × TS Delta × DE Correction
//
// Thompson Sampling (primary): Per-operator Bayesian adaptation with Beta-Bernoulli posteriors.
//   - Binary success/failure signals with path-weighted feedback
//   - Time-based decay (configurable half-life)
//   - IPW correction for selection bias
//   - Saturation detection with relative performance mode
//   - ±20% delta range
//
// Differential Evolution (secondary): Joint weight vector optimization for operator synergies.
//   - ±5% correction range (narrower, supplementary role)
//   - Independent fitness function (squared error from ideal, not TS-dependent)
//   - Conflict detection with automatic dampening
//
// Risk mitigations: warm-up period, exploration rounds, crash bonus,
// selective AI reset, starvation prevention, Phase 12 feature collection.
package fuzzer

import (
	"context"
	"encoding/csv"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

// FeedbackSource identifies which execution path produced the result.
type FeedbackSource int

const (
	SourceMutate FeedbackSource = iota // mutateProgRequest (async, high volume, noisier)
	SourceSmash                        // smashJob (sync, medium volume)
	SourceFocus                        // focusJob (sync, low volume, highest quality)
)

const (
	dezzerWindowSize = 100 // sliding window per operator
	dezzerPopSize    = 10  // DE population size
	dezzerEvolveEvery = 100 // evolve DE every N records
	dezzerNumOps     = 6   // squash, splice, insert, mutate_arg, remove, reorder

	// Thompson Sampling.
	dezzerWarmupRecords       = 1000  // delta=1.0 during warm-up (no TS/DE applied)
	dezzerDecayIntervalSec    = 30    // time-based decay interval (seconds)
	dezzerDecayFactor         = 0.9   // alpha/beta *= this each decay interval (~3.3 min half-life)
	dezzerAlphaFloor          = 1.0   // minimum alpha (preserves prior, prevents starvation)
	dezzerBetaFloor           = 1.0   // minimum beta
	dezzerSaturationThreshold = 0.001 // mean success prob below this → saturation mode

	// TS delta range.
	dezzerTSDeltaLimit = 0.20 // ±20%

	// DE correction range (secondary, narrower).
	dezzerDECorrLimit       = 0.05 // ±5%
	dezzerF                 = 0.5  // DE mutation factor
	dezzerCR                = 0.7  // DE crossover rate

	// Path weights (feedback quality scaling).
	dezzerWeightMutate = 1.0
	dezzerWeightSmash  = 2.0
	dezzerWeightFocus  = 3.0

	// Exploration rounds.
	dezzerExploreEvery  = 5000 // exploration round every N records
	dezzerExploreLength = 50   // records in exploration mode (neutral delta)

	// Inverse Propensity Weighting cap.
	dezzerIPWCap = 5.0

	// Conflict detection.
	dezzerConflictThreshold = 3    // N/5 operators disagree → dampen DE
	dezzerDampenedCorrLimit = 0.02 // ±2% when dampened
	dezzerDampenRecoveryGen = 10   // generations until DE range restored

	// DE stagnation.
	dezzerStagnantLimit = 50
	dezzerKeepBest      = 3

	// Crash bonus.
	dezzerCrashBonus = 10.0

	// Phase 12 feature log.
	dezzerFeatureLogSize = 100000

	// Phase 8b: Op-pair conditional TS.
	dezzerPairMinData = 50 // minimum observations before using pair TS (fallback to single-op)

	// Phase 8e: Per-cluster TS.
	numClusters          = 10
	dezzerClusterMinData = 100 // per-cluster fallback threshold

	// Phase 11a: EMA + CUSUM change-point detection.
	dezzerEMASmoothingAlpha  = 0.05  // EMA smoothing factor (slow tracker)
	dezzerCUSUMThreshold     = 5.0   // CUSUM alarm threshold (H)
	dezzerCUSUMDrift         = 0.01  // CUSUM allowance/drift parameter (k)
	dezzerCUSUMSampleEvery   = 100   // only update CUSUM every N records (noise reduction)
	dezzerCUSUMMaxResetsWin  = 3     // max resets allowed per window before circuit breaker
	dezzerCUSUMBreakerWinSec = 600   // circuit breaker window (10 minutes)

	// Phase 8c: Multi-objective meta-bandit.
	NumObjectives     = 3
	ObjCoverage       = 0
	ObjMemorySafety   = 1
	ObjPrivEsc        = 2
	objEpochSize      = 100   // re-select objective every N records
	objCovFloorInit   = 0.70  // initial coverage floor (first hour)
	objCovFloorMid    = 0.50  // mid-phase floor (1-4 hours)
	objCovFloorLate   = 0.30  // late-phase floor (4+ hours)
)

// opNames maps operator index to name.
var opNames = [dezzerNumOps]string{"squash", "splice", "insert", "mutate_arg", "remove", "reorder"}

// opNameToIndex returns the index for a given operator name, or -1 if unknown.
func opNameToIndex(name string) int {
	for i, n := range opNames {
		if n == name {
			return i
		}
	}
	return -1
}

// Phase 12 B4: Sub-op names for two-level action space.
// Each parent op maps to 2-6 sub-ops. Total: 17 feasible arms.
var subOpNames = map[string][]string{
	"mutate_arg": {"mutate_arg_int", "mutate_arg_ptr", "mutate_arg_string", "mutate_arg_array", "mutate_arg_struct", "mutate_arg_resource"},
	"splice":     {"splice_same_cluster", "splice_cross_cluster"},
	"squash":     {"squash_adjacent", "squash_distant", "squash_merge_args"},
	"insert":     {"insert_related", "insert_random", "insert_resource"},
	"remove":     {"remove_random"},
	"reorder":    {"reorder_deps", "reorder_random"},
}

// maxSubOps is the maximum number of sub-ops for any parent op.
const maxSubOps = 6

// subOpToIndex returns the index of a sub-op within its parent op, or -1 if unknown.
func subOpToIndex(parentOp, subOp string) int {
	subs, ok := subOpNames[parentOp]
	if !ok {
		return -1
	}
	for i, s := range subs {
		if s == subOp {
			return i
		}
	}
	return -1
}

// parentOp extracts the 6-op parent name from a sub-op name or returns the name as-is.
// Phase 12 B4: Ensures RecordResult always receives a valid 6-op name.
func parentOp(op string) string {
	if opNameToIndex(op) >= 0 {
		return op // already a valid parent op
	}
	// Try to find which parent this sub-op belongs to.
	for parent, subs := range subOpNames {
		for _, s := range subs {
			if s == op {
				return parent
			}
		}
	}
	return op // unknown — return as-is, will be caught by opNameToIndex
}

// DEzzer is a hybrid Thompson Sampling + Differential Evolution optimizer.
// TS provides fast per-operator adaptation; DE finds operator combination synergies.
// 4-Layer: Default × AI Base × TS Delta × DE Correction = Final Weights.
type DEzzer struct {
	mu sync.Mutex

	// Per-operator performance tracking (sliding window).
	opStats [dezzerNumOps]OperatorStats

	// Thompson Sampling posteriors (per operator).
	alpha [dezzerNumOps]float64
	beta  [dezzerNumOps]float64

	// DE population (correction vectors, ±5%).
	population [dezzerPopSize]WeightVector
	fitness    [dezzerPopSize]float64
	bestIdx    int
	generation int

	// AI base weights (layer 2).
	aiBaseWeights WeightVector

	// State tracking.
	totalRecords  int64
	warmupDone    bool
	lastDecayNano atomic.Int64 // Phase 11a: atomic unix-nano timestamp for decay check
	saturated     bool

	// Exploration mode.
	explorationMode bool
	explorationLeft int

	// Conflict detection.
	conflictDampened bool
	dampenGensLeft   int

	// DE stagnation.
	stagnantGens int
	lastBestCorr WeightVector

	// Phase 12 ML feature log (atomic ring buffer).
	featureLog      [dezzerFeatureLogSize]FeatureTuple
	featureLogIdx   atomic.Int64 // Phase 11a: atomic monotonic counter replaces time.Now()
	featureLogLen   int

	// Phase 8b: Op-pair conditional TS.
	pairAlpha [dezzerNumOps][dezzerNumOps]float64 // pairAlpha[prevOp][nextOp]
	pairBeta  [dezzerNumOps][dezzerNumOps]float64
	pairCount [dezzerNumOps][dezzerNumOps]int64

	// Phase 8e: Per-cluster TS.
	clusterAlpha [numClusters][dezzerNumOps]float64
	clusterBeta  [numClusters][dezzerNumOps]float64
	clusterCount [numClusters]int64

	// Phase 12 B3: Cross-product TS (cluster x objective = 6x3 = 18 contexts, 108 posteriors).
	crossAlpha [numClusters][NumObjectives][dezzerNumOps]float64
	crossBeta  [numClusters][NumObjectives][dezzerNumOps]float64
	crossCount [numClusters][NumObjectives]int64

	// Phase 8c: Multi-objective meta-bandit.
	objAlpha   [NumObjectives][dezzerNumOps]float64
	objBeta    [NumObjectives][dezzerNumOps]float64
	objRewards [NumObjectives]float64 // UCB-1 cumulative reward
	objCounts  [NumObjectives]int64   // UCB-1 pull counts
	currentObj      int            // current epoch objective
	currentObjCache atomic.Int64   // lock-free cache of currentObj for hot-path reads
	epochLeft  int                    // remaining records in this epoch
	startTime  time.Time             // fuzzer start time (dynamic coverage floor)

	// Phase 11a: EMA + CUSUM change-point detection.
	emaRate     float64 // exponential moving average of success rate
	cusumHi     float64 // CUSUM upper statistic (detecting increase)
	cusumLo     float64 // CUSUM lower statistic (detecting decrease)
	cusumResets int64   // number of CUSUM regime changes detected

	// Phase 11a: CUSUM circuit breaker (prevents over-triggering).
	cusumDisabled     bool      // true when circuit breaker has tripped
	cusumDisableTime  time.Time // when the breaker tripped
	cusumRecentResets []int64   // timestamps (unix seconds) of recent resets within window

	// Phase 11l: CUSUM shadow pause during BO parameter transitions.
	cusumShadowUntil time.Time // CUSUM paused until this time (zero = not paused)

	// Phase 12 A5: Normalization + CUSUM mutual exclusion (60s suppression window).
	lastNormalization time.Time // when normalization last ran (suppress CUSUM for 60s after)
	lastCUSUMReset    time.Time // when CUSUM last reset (suppress normalization for 60s after)

	// Phase 12 B1: Feature enrichment references.
	entropyRef        *atomic.Int64 // pointer to fuzzer.coverageEntropy (lock-free read)
	configVersion     int           // increments when eBPF map config changes (NEW-5)
	recordsSinceCUSUM int64         // records since last CUSUM reset

	// Phase 12 B4: Sub-op posteriors (global level only — pair TS stays at 6-op granularity).
	subOpAlpha [dezzerNumOps][maxSubOps]float64
	subOpBeta  [dezzerNumOps][maxSubOps]float64
	subOpCount [dezzerNumOps][maxSubOps]int64

	// Phase 12 C1: BO-tunable overrides (0 = use constant default).
	boDecayFactor  float64 // overrides dezzerDecayFactor when > 0
	boTSDeltaLimit float64 // overrides dezzerTSDeltaLimit when > 0

	// Phase 12 B4: stat counter for pair TS fallback (unknown prevOp).
	statPairTSFallback *stat.Val

	// Phase 11a: CUSUM stat references (registered by fuzzer's stats.go).
	statCusumResets *stat.Val
	statCusumValue  *stat.Val
	statEmaRate     *stat.Val

	logf func(level int, msg string, args ...any)
}

// OperatorStats tracks recent performance of a single mutation operator.
type OperatorStats struct {
	Window    [dezzerWindowSize]OpResult
	WindowIdx int
	Count     int64 // total records ever
}

// OpResult is a single operator execution result.
type OpResult struct {
	CovGainBits int
}

// WeightVector holds per-operator delta multipliers.
// Values are centered on 1.0 (no change from base).
type WeightVector struct {
	Squash    float64
	Splice    float64
	Insert    float64
	MutateArg float64
	Remove    float64
	Reorder   float64
}

// FeatureTuple stores (context, operator, reward) for Phase 12 ML training.
type FeatureTuple struct {
	Timestamp        int64          // monotonic record ID
	OpIdx            int            // operator index
	CovGain          int            // raw coverage gain
	Success          bool           // covGain > 0
	Source           FeedbackSource // which feedback path
	Saturated        bool           // was system in saturation mode
	ProgramCluster   int            // Phase 12 B1: kernel subsystem cluster (0-9)
	CoverageEntropy  int            // Phase 12 B1: Shannon entropy x1000
	EMARate          int            // Phase 12 B1: DEzzer EMA success rate x10000
	RecordsSinceCUSUM int64         // Phase 12 B1: records since last CUSUM reset
	PrevOp           int            // Phase 12 B1: previous operator index (-1 if none)
	ConfigVersion    int            // Phase 12 B1: eBPF config version (NEW-5)
}

// NewDEzzer creates a new hybrid TS+DE optimizer.
func NewDEzzer(logf func(level int, msg string, args ...any)) *DEzzer {
	d := &DEzzer{
		logf:          logf,
		aiBaseWeights: WeightVector{1.0, 1.0, 1.0, 1.0, 1.0, 1.0},
		startTime:     time.Now(),
		epochLeft:     objEpochSize,
		emaRate:       0.5, // neutral initial EMA
	}
	d.lastDecayNano.Store(time.Now().UnixNano())
	// Initialize TS posteriors with uniform prior.
	for i := 0; i < dezzerNumOps; i++ {
		d.alpha[i] = dezzerAlphaFloor
		d.beta[i] = dezzerBetaFloor
	}
	// Phase 8b: Initialize pair TS with uniform prior.
	for i := 0; i < dezzerNumOps; i++ {
		for j := 0; j < dezzerNumOps; j++ {
			d.pairAlpha[i][j] = 1.0
			d.pairBeta[i][j] = 1.0
		}
	}
	// Phase 8e: Initialize cluster TS with uniform prior.
	for c := 0; c < numClusters; c++ {
		for i := 0; i < dezzerNumOps; i++ {
			d.clusterAlpha[c][i] = 1.0
			d.clusterBeta[c][i] = 1.0
		}
	}
	// Phase 8c: Initialize multi-objective TS with uniform prior.
	for o := 0; o < NumObjectives; o++ {
		for i := 0; i < dezzerNumOps; i++ {
			d.objAlpha[o][i] = 1.0
			d.objBeta[o][i] = 1.0
		}
	}
	// Phase 12 B4: Initialize sub-op TS with uniform prior.
	for i := 0; i < dezzerNumOps; i++ {
		subs := subOpNames[opNames[i]]
		for j := 0; j < len(subs); j++ {
			d.subOpAlpha[i][j] = 1.0
			d.subOpBeta[i][j] = 1.0
		}
	}
	// Initialize DE population around 1.0 (±5%).
	rnd := rand.New(rand.NewSource(42))
	for i := range d.population {
		d.population[i] = randomVector(rnd, dezzerDECorrLimit)
	}
	return d
}

// RecordResult records an operator execution result for TS+DE optimization.
// Phase 8b: prevOp tracks the previous mutation operator for pair TS ("" = no pair).
// Phase 8e: cluster is the kernel subsystem cluster index (-1 = global only).
func (d *DEzzer) RecordResult(op, prevOp, subOp string, covGainBits int, source FeedbackSource, cluster int) {
	idx := opNameToIndex(op)
	if idx < 0 {
		if d.logf != nil {
			d.logf(1, "PROBE: DEzzer unknown op '%s' dropped", op)
		}
		return
	}

	success := covGainBits > 0
	prevIdx := opNameToIndex(prevOp)

	// Phase 12 B1: Pre-compute lock-protected values for feature enrichment.
	// Quick lock to snapshot emaRate + recordsSinceCUSUM, then recordFeature outside main lock.
	d.mu.Lock()
	emaRateSnap := int(d.emaRate * 10000)
	recordsSinceCUSUMSnap := d.recordsSinceCUSUM
	d.mu.Unlock()

	// Phase 11a: Record feature with atomic counter (no lock needed for ring buffer write).
	// Phase 12 B1: Enriched with context fields.
	d.recordFeature(idx, covGainBits, success, source, cluster, emaRateSnap, recordsSinceCUSUMSnap, prevIdx)

	d.mu.Lock()

	// 1. Update sliding window.
	stats := &d.opStats[idx]
	wIdx := int(stats.Count % int64(dezzerWindowSize))
	stats.Window[wIdx] = OpResult{CovGainBits: covGainBits}
	stats.WindowIdx = (wIdx + 1) % dezzerWindowSize
	stats.Count++
	d.totalRecords++
	d.recordsSinceCUSUM++ // Phase 12 B1: track records since last CUSUM reset

	// 2. Time-based decay for TS posteriors (Phase 11a: atomic timestamp check).
	d.maybeDecay()

	// 3. Update TS posterior (binary signal + path weight + IPW).
	pathWeight := d.pathWeight(source)
	ipwWeight := d.ipwWeight(idx)
	weight := math.Min(pathWeight*ipwWeight, dezzerIPWCap)

	// Easy-coverage filter: reduce weight during warm-up.
	if !d.warmupDone {
		weight *= 0.5
	}

	if success {
		d.alpha[idx] += weight
	} else {
		d.beta[idx] += weight
	}

	// Phase 8b: Update pair TS if we have a valid prevOp.
	// (prevIdx already computed above for B1 feature enrichment)
	if prevIdx >= 0 {
		if success {
			d.pairAlpha[prevIdx][idx] += weight
		} else {
			d.pairBeta[prevIdx][idx] += weight
		}
		d.pairCount[prevIdx][idx]++
	} else if prevOp != "" && d.statPairTSFallback != nil {
		// Phase 12 B4: Track pair TS fallback when prevOp is unknown.
		d.statPairTSFallback.Add(1)
	}

	// Phase 8e: Update per-cluster TS if valid cluster.
	if cluster >= 0 && cluster < numClusters {
		if success {
			d.clusterAlpha[cluster][idx] += weight
		} else {
			d.clusterBeta[cluster][idx] += weight
		}
		d.clusterCount[cluster]++
	}

	// Phase 12 B3: Update cross-product TS (cluster x objective).
	if cluster >= 0 && cluster < numClusters && d.currentObj >= 0 && d.currentObj < NumObjectives {
		if success {
			d.crossAlpha[cluster][d.currentObj][idx] += weight
		} else {
			d.crossBeta[cluster][d.currentObj][idx] += weight
		}
		d.crossCount[cluster][d.currentObj]++
	}

	// Phase 8c: Update objective-specific TS.
	if d.currentObj >= 0 && d.currentObj < NumObjectives {
		if success {
			d.objAlpha[d.currentObj][idx] += weight
		} else {
			d.objBeta[d.currentObj][idx] += weight
		}
	}

	// Phase 12 B4: Update sub-op posteriors (two-level action space).
	if subOp != "" {
		subIdx := subOpToIndex(op, subOp)
		if subIdx >= 0 {
			if success {
				d.subOpAlpha[idx][subIdx] += weight
			} else {
				d.subOpBeta[idx][subIdx] += weight
			}
			d.subOpCount[idx][subIdx]++
		}
	}

	// Phase 11a: EMA + CUSUM change-point detection (every N records to reduce noise).
	if d.totalRecords%dezzerCUSUMSampleEvery == 0 {
		d.updateEMACUSUM(success)
	}

	// 5. Check warm-up completion.
	if !d.warmupDone && d.totalRecords >= dezzerWarmupRecords {
		d.warmupDone = true
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer warm-up complete (%d records), activating TS+DE optimization", d.totalRecords)
		}
	}

	// 6. Exploration round management.
	if d.totalRecords%dezzerExploreEvery == 0 && d.warmupDone {
		d.explorationMode = true
		d.explorationLeft = dezzerExploreLength
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer exploration round (next %d records with neutral delta)", dezzerExploreLength)
		}
	}
	if d.explorationMode {
		d.explorationLeft--
		if d.explorationLeft <= 0 {
			d.explorationMode = false
		}
	}

	// 7. DE evolution (Phase 11a: snapshot pattern — copy state, evolve outside lock).
	needEvolve := d.totalRecords%dezzerEvolveEvery == 0 && d.warmupDone
	var deSnapshot deEvolveSnapshot
	if needEvolve {
		d.recalcDEFitness()
		deSnapshot = d.snapshotDEState()
	}

	// Phase 8c: Epoch management — re-select objective periodically.
	d.epochLeft--
	if d.epochLeft <= 0 && d.warmupDone {
		d.currentObj = d.selectObjective()
		d.currentObjCache.Store(int64(d.currentObj))
		d.epochLeft = objEpochSize
	}

	d.mu.Unlock()

	// Phase 11a: DE evolution outside the lock.
	if needEvolve {
		newPop, newFit, newBest, newGen := d.evolveDEOutsideLock(deSnapshot)
		d.mu.Lock()
		d.applyDEResults(newPop, newFit, newBest, newGen)
		d.mu.Unlock()
	}
}

// RecordCrash gives a bonus to the operator that triggered a crash.
// In saturation phase, crashes are the most valuable signal.
func (d *DEzzer) RecordCrash(op string) {
	idx := opNameToIndex(op)
	if idx < 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.alpha[idx] += dezzerCrashBonus
	if d.logf != nil {
		d.logf(0, "PROBE: DEzzer crash bonus for '%s' (alpha now %.1f)", op, d.alpha[idx])
	}
}

// RecordAnamnesisBonus applies an exploit-assessment bonus to the mutation operator's
// Thompson Sampling posterior. Called after Anamnesis assessment in processResult.
// Phase 14 D9: Connect Anamnesis exploit assessment to DEzzer mutation optimizer.
func (d *DEzzer) RecordAnamnesisBonus(op string, cluster int, multiplier float64) {
	idx := opNameToIndex(op)
	if idx < 0 || cluster < 0 || cluster >= numClusters {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Add bonus alpha proportional to multiplier.
	// e.g., 1.2 -> 2.0, 1.5 -> 5.0, 2.0 -> 10.0
	bonus := (multiplier - 1.0) * 10.0
	d.alpha[idx] += bonus
	if cluster < numClusters {
		d.clusterAlpha[cluster][idx] += bonus
	}

	if d.logf != nil {
		d.logf(1, "PROBE: DEzzer Anamnesis bonus for '%s' cluster=%d mult=%.1f (alpha +%.1f)",
			op, cluster, multiplier, bonus)
	}
}

// SelectSubOp returns a sub-op name for the given parent op using Thompson Sampling.
// Phase 12 B4: Two-level action space — proportional selection over sub-op posteriors.
// Returns "" if the parent has no sub-ops or only one (deterministic).
func (d *DEzzer) SelectSubOp(parentOp string) string {
	subs, ok := subOpNames[parentOp]
	if !ok || len(subs) == 0 {
		return ""
	}
	if len(subs) == 1 {
		return subs[0]
	}
	pidx := opNameToIndex(parentOp)
	if pidx < 0 {
		return subs[0]
	}
	d.mu.Lock()
	// Compute posterior means for proportional selection.
	var probs [maxSubOps]float64
	total := 0.0
	for i := 0; i < len(subs); i++ {
		a := math.Max(1.0, d.subOpAlpha[pidx][i])
		b := math.Max(1.0, d.subOpBeta[pidx][i])
		probs[i] = a / (a + b)
		total += probs[i]
	}
	d.mu.Unlock()

	// Proportional selection (roulette wheel).
	r := rand.Float64() * total
	cum := 0.0
	for i := 0; i < len(subs); i++ {
		cum += probs[i]
		if r <= cum {
			return subs[i]
		}
	}
	return subs[len(subs)-1]
}

// GetCurrentWeights returns final weights: Default × AI Base × TS Delta × DE Correction.
func (d *DEzzer) GetCurrentWeights() prog.MutateOpts {
	d.mu.Lock()
	defer d.mu.Unlock()

	defaults := prog.DefaultMutateOpts

	// During warm-up or exploration, use neutral delta (Default × AI Base only).
	if !d.warmupDone || d.explorationMode {
		return prog.MutateOpts{
			ExpectedIterations: defaults.ExpectedIterations,
			MutateArgCount:     defaults.MutateArgCount,
			SquashWeight:       maxInt(1, int(float64(defaults.SquashWeight)*d.aiBaseWeights.Squash)),
			SpliceWeight:       maxInt(1, int(float64(defaults.SpliceWeight)*d.aiBaseWeights.Splice)),
			InsertWeight:       maxInt(1, int(float64(defaults.InsertWeight)*d.aiBaseWeights.Insert)),
			MutateArgWeight:    maxInt(1, int(float64(defaults.MutateArgWeight)*d.aiBaseWeights.MutateArg)),
			RemoveCallWeight:   maxInt(1, int(float64(defaults.RemoveCallWeight)*d.aiBaseWeights.Remove)),
			ReorderWeight:      maxInt(1, int(float64(defaults.ReorderWeight)*d.aiBaseWeights.Reorder)),
		}
	}

	tsDelta := d.computeTSDelta()
	deCorr := d.population[d.bestIdx]

	return prog.MutateOpts{
		ExpectedIterations: defaults.ExpectedIterations,
		MutateArgCount:     defaults.MutateArgCount,
		SquashWeight:       maxInt(1, int(float64(defaults.SquashWeight)*d.aiBaseWeights.Squash*tsDelta.Squash*deCorr.Squash)),
		SpliceWeight:       maxInt(1, int(float64(defaults.SpliceWeight)*d.aiBaseWeights.Splice*tsDelta.Splice*deCorr.Splice)),
		InsertWeight:       maxInt(1, int(float64(defaults.InsertWeight)*d.aiBaseWeights.Insert*tsDelta.Insert*deCorr.Insert)),
		MutateArgWeight:    maxInt(1, int(float64(defaults.MutateArgWeight)*d.aiBaseWeights.MutateArg*tsDelta.MutateArg*deCorr.MutateArg)),
		RemoveCallWeight:   maxInt(1, int(float64(defaults.RemoveCallWeight)*d.aiBaseWeights.Remove*tsDelta.Remove*deCorr.Remove)),
		ReorderWeight:      maxInt(1, int(float64(defaults.ReorderWeight)*d.aiBaseWeights.Reorder*tsDelta.Reorder*deCorr.Reorder)),
	}
}

// GetCurrentWeightsForPair returns weights considering pair TS and cluster TS.
// Phase 8b: If prevOp has enough pair data, use pair-conditioned TS delta.
// Phase 8e: If cluster has enough data, use cluster-specific TS delta.
func (d *DEzzer) GetCurrentWeightsForPair(prevOp string, cluster int) prog.MutateOpts {
	d.mu.Lock()
	defer d.mu.Unlock()

	defaults := prog.DefaultMutateOpts

	// During warm-up or exploration, use neutral delta (Default × AI Base only).
	if !d.warmupDone || d.explorationMode {
		return prog.MutateOpts{
			ExpectedIterations: defaults.ExpectedIterations,
			MutateArgCount:     defaults.MutateArgCount,
			SquashWeight:       maxInt(1, int(float64(defaults.SquashWeight)*d.aiBaseWeights.Squash)),
			SpliceWeight:       maxInt(1, int(float64(defaults.SpliceWeight)*d.aiBaseWeights.Splice)),
			InsertWeight:       maxInt(1, int(float64(defaults.InsertWeight)*d.aiBaseWeights.Insert)),
			MutateArgWeight:    maxInt(1, int(float64(defaults.MutateArgWeight)*d.aiBaseWeights.MutateArg)),
			RemoveCallWeight:   maxInt(1, int(float64(defaults.RemoveCallWeight)*d.aiBaseWeights.Remove)),
			ReorderWeight:      maxInt(1, int(float64(defaults.ReorderWeight)*d.aiBaseWeights.Reorder)),
		}
	}

	// Compute TS delta: prefer pair TS > cluster TS > global TS.
	tsDelta := d.computeTSDeltaLayered(prevOp, cluster)
	deCorr := d.population[d.bestIdx]

	return prog.MutateOpts{
		ExpectedIterations: defaults.ExpectedIterations,
		MutateArgCount:     defaults.MutateArgCount,
		SquashWeight:       maxInt(1, int(float64(defaults.SquashWeight)*d.aiBaseWeights.Squash*tsDelta.Squash*deCorr.Squash)),
		SpliceWeight:       maxInt(1, int(float64(defaults.SpliceWeight)*d.aiBaseWeights.Splice*tsDelta.Splice*deCorr.Splice)),
		InsertWeight:       maxInt(1, int(float64(defaults.InsertWeight)*d.aiBaseWeights.Insert*tsDelta.Insert*deCorr.Insert)),
		MutateArgWeight:    maxInt(1, int(float64(defaults.MutateArgWeight)*d.aiBaseWeights.MutateArg*tsDelta.MutateArg*deCorr.MutateArg)),
		RemoveCallWeight:   maxInt(1, int(float64(defaults.RemoveCallWeight)*d.aiBaseWeights.Remove*tsDelta.Remove*deCorr.Remove)),
		ReorderWeight:      maxInt(1, int(float64(defaults.ReorderWeight)*d.aiBaseWeights.Reorder*tsDelta.Reorder*deCorr.Reorder)),
	}
}

// computeTSDeltaLayered computes TS delta using the best available data:
// Phase 12 B3: pair TS → cross-product TS → cluster TS (+A3 blend) → global TS (+A3 blend).
func (d *DEzzer) computeTSDeltaLayered(prevOp string, cluster int) WeightVector {
	prevIdx := opNameToIndex(prevOp)

	// Try pair TS first (Phase 8b) — most specific, operator-pair conditioning.
	if prevIdx >= 0 {
		totalPairData := int64(0)
		for j := 0; j < dezzerNumOps; j++ {
			totalPairData += d.pairCount[prevIdx][j]
		}
		if totalPairData >= dezzerPairMinData {
			return d.computePairTSDelta(prevIdx)
		}
	}

	// Phase 12 B3: Try cross-product TS (cluster x objective).
	// When active, SKIP A3 objective blend (NEW-1: already encodes objective dimension).
	if cluster >= 0 && cluster < numClusters &&
		d.currentObj >= 0 && d.currentObj < NumObjectives &&
		d.crossCount[cluster][d.currentObj] >= 50 {
		return d.computeCrossTSDelta(cluster, d.currentObj)
	}

	// Try cluster TS (Phase 8e) + A3 objective blend.
	if cluster >= 0 && cluster < numClusters && d.clusterCount[cluster] >= dezzerClusterMinData {
		clusterDelta := d.computeClusterTSDelta(cluster)
		// Phase 12 A3: Blend with objective TS if sufficient data.
		if d.currentObj >= 0 && d.currentObj < NumObjectives && d.objCounts[d.currentObj] >= 200 {
			objDelta := d.computeObjectiveTSDelta(d.currentObj)
			return blendWeightVectors(clusterDelta, 0.9, objDelta, 0.1)
		}
		return clusterDelta
	}

	// Fallback to global TS + A3 objective blend.
	globalDelta := d.computeTSDelta()
	// Phase 12 A3: Blend with objective TS if sufficient data.
	if d.currentObj >= 0 && d.currentObj < NumObjectives && d.objCounts[d.currentObj] >= 200 {
		objDelta := d.computeObjectiveTSDelta(d.currentObj)
		return blendWeightVectors(globalDelta, 0.9, objDelta, 0.1)
	}
	return globalDelta
}

// computePairTSDelta computes TS delta conditioned on prevOp.
func (d *DEzzer) computePairTSDelta(prevIdx int) WeightVector {
	var probs [dezzerNumOps]float64
	for j := 0; j < dezzerNumOps; j++ {
		probs[j] = d.pairAlpha[prevIdx][j] / (d.pairAlpha[prevIdx][j] + d.pairBeta[prevIdx][j])
	}
	return d.probsToTSDelta(probs)
}

// computeClusterTSDelta computes TS delta for a specific kernel subsystem cluster.
func (d *DEzzer) computeClusterTSDelta(cluster int) WeightVector {
	var probs [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		probs[i] = d.clusterAlpha[cluster][i] / (d.clusterAlpha[cluster][i] + d.clusterBeta[cluster][i])
	}
	return d.probsToTSDelta(probs)
}

// computeObjectiveTSDelta computes TS delta for the current objective.
// Phase 12 A3: Uses objAlpha/objBeta for objective-aware blending.
func (d *DEzzer) computeObjectiveTSDelta(objIdx int) WeightVector {
	var probs [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		probs[i] = d.objAlpha[objIdx][i] / (d.objAlpha[objIdx][i] + d.objBeta[objIdx][i])
	}
	return d.probsToTSDelta(probs)
}

// computeCrossTSDelta computes TS delta for the (cluster, objective) cross-product.
// Phase 12 B3: 108 Beta posteriors for context-aware operator selection.
func (d *DEzzer) computeCrossTSDelta(cluster, objIdx int) WeightVector {
	var probs [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		a := d.crossAlpha[cluster][objIdx][i]
		b := d.crossBeta[cluster][objIdx][i]
		if a+b > 0 {
			probs[i] = a / (a + b)
		} else {
			probs[i] = 0.5 // uninformative prior
		}
	}
	// Blend with global TS when cross-product data is sparse (50-200 range).
	if d.crossCount[cluster][objIdx] < 200 {
		globalProbs := d.globalProbs()
		blendRatio := float64(d.crossCount[cluster][objIdx]) / 200.0 // 0.25 at 50, 1.0 at 200
		for i := 0; i < dezzerNumOps; i++ {
			probs[i] = blendRatio*probs[i] + (1.0-blendRatio)*globalProbs[i]
		}
	}
	return d.probsToTSDelta(probs)
}

// globalProbs returns global success probabilities for blending.
func (d *DEzzer) globalProbs() [dezzerNumOps]float64 {
	var probs [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		probs[i] = d.alpha[i] / (d.alpha[i] + d.beta[i])
	}
	return probs
}

// blendWeightVectors blends two weight vectors: result = a*va + b*vb.
// Phase 12 A3: Used for objective TS blending (0.9*layered + 0.1*obj).
func blendWeightVectors(va WeightVector, a float64, vb WeightVector, b float64) WeightVector {
	return WeightVector{
		Squash:    va.Squash*a + vb.Squash*b,
		Splice:    va.Splice*a + vb.Splice*b,
		Insert:    va.Insert*a + vb.Insert*b,
		MutateArg: va.MutateArg*a + vb.MutateArg*b,
		Remove:    va.Remove*a + vb.Remove*b,
		Reorder:   va.Reorder*a + vb.Reorder*b,
	}
}

// probsToTSDelta converts success probabilities into a TS delta weight vector.
func (d *DEzzer) probsToTSDelta(probs [dezzerNumOps]float64) WeightVector {
	meanProb := 0.0
	for _, p := range probs {
		meanProb += p
	}
	meanProb /= float64(dezzerNumOps)

	limit := d.getTSDeltaLimit() // Phase 12 C1: BO-tunable
	lo := 1.0 - limit
	hi := 1.0 + limit
	var arr [dezzerNumOps]float64

	maxProb := 0.0
	for _, p := range probs {
		if p > maxProb {
			maxProb = p
		}
	}

	if meanProb < dezzerSaturationThreshold {
		// Saturation mode.
		if maxProb < 1e-10 {
			maxProb = 1e-10
		}
		for i := 0; i < dezzerNumOps; i++ {
			relative := probs[i] / maxProb
			arr[i] = clampFloat(0.6+0.8*relative, lo, hi)
		}
	} else {
		if meanProb < 1e-10 {
			meanProb = 1e-10
		}
		for i := 0; i < dezzerNumOps; i++ {
			arr[i] = clampFloat(probs[i]/meanProb, lo, hi)
		}
	}
	return arrToVec(arr)
}

// SetAIBaseWeights updates the AI base weights with selective reset.
// Small changes → soft TS reset (30% preserve) + DE kept.
// Large changes → hard reset both TS and DE.
// SetBOOverrides sets BO-tunable parameters. Phase 12 C1.
// decayFactor=0 means use default constant, tsDeltaLimit=0 means use default constant.
func (d *DEzzer) SetBOOverrides(decayFactor, tsDeltaLimit float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.boDecayFactor = decayFactor
	d.boTSDeltaLimit = tsDeltaLimit
}

// getDecayFactor returns the effective decay factor (BO override or default).
func (d *DEzzer) getDecayFactor() float64 {
	if d.boDecayFactor > 0 {
		return d.boDecayFactor
	}
	return dezzerDecayFactor
}

// getTSDeltaLimit returns the effective TS delta limit (BO override or default).
func (d *DEzzer) getTSDeltaLimit() float64 {
	if d.boTSDeltaLimit > 0 {
		return d.boTSDeltaLimit
	}
	return dezzerTSDeltaLimit
}

func (d *DEzzer) SetAIBaseWeights(opts prog.MutateOpts) {
	d.mu.Lock()
	defer d.mu.Unlock()

	defaults := prog.DefaultMutateOpts
	newBase := WeightVector{
		Squash:    safeDiv(float64(opts.SquashWeight), float64(defaults.SquashWeight)),
		Splice:    safeDiv(float64(opts.SpliceWeight), float64(defaults.SpliceWeight)),
		Insert:    safeDiv(float64(opts.InsertWeight), float64(defaults.InsertWeight)),
		MutateArg: safeDiv(float64(opts.MutateArgWeight), float64(defaults.MutateArgWeight)),
		Remove:    safeDiv(float64(opts.RemoveCallWeight), float64(defaults.RemoveCallWeight)),
		Reorder:   safeDiv(float64(opts.ReorderWeight), float64(maxInt(1, defaults.ReorderWeight))),
	}

	// Compute change magnitude.
	oldArr := vecToArr(d.aiBaseWeights)
	newArr := vecToArr(newBase)
	change := 0.0
	for i := 0; i < dezzerNumOps; i++ {
		change += math.Abs(newArr[i] - oldArr[i])
	}

	d.aiBaseWeights = newBase

	if change < 0.3 {
		// Small change: soft reset TS (preserve 30%), keep DE.
		for i := 0; i < dezzerNumOps; i++ {
			d.alpha[i] = dezzerAlphaFloor + 0.3*(d.alpha[i]-dezzerAlphaFloor)
			d.beta[i] = dezzerBetaFloor + 0.3*(d.beta[i]-dezzerBetaFloor)
		}
		// Inject AI direction hint into TS prior.
		for i := 0; i < dezzerNumOps; i++ {
			if newArr[i] > oldArr[i] {
				d.alpha[i] += 2.0 // AI says boost → slight positive prior
			} else if newArr[i] < oldArr[i] {
				d.beta[i] += 2.0 // AI says suppress → slight negative prior
			}
		}
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer AI base minor update (change=%.2f) — TS soft reset, DE kept", change)
		}
	} else {
		// Large change: hard reset TS + DE.
		for i := 0; i < dezzerNumOps; i++ {
			d.alpha[i] = dezzerAlphaFloor
			d.beta[i] = dezzerBetaFloor
			// Inject AI direction hint.
			if newArr[i] > 1.0 {
				d.alpha[i] += 2.0
			} else if newArr[i] < 1.0 {
				d.beta[i] += 2.0
			}
		}
		rnd := rand.New(rand.NewSource(d.totalRecords))
		for i := range d.population {
			d.population[i] = randomVector(rnd, dezzerDECorrLimit)
			d.fitness[i] = 0
		}
		d.bestIdx = 0
		d.generation = 0
		d.stagnantGens = 0
		d.lastBestCorr = WeightVector{}
		d.conflictDampened = false
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer AI base major update (change=%.2f) — full TS+DE reset", change)
		}
	}

	if d.logf != nil {
		d.logf(0, "PROBE: DEzzer AI base — Sq:%.2f Sp:%.2f In:%.2f MA:%.2f Rm:%.2f Ro:%.2f",
			d.aiBaseWeights.Squash, d.aiBaseWeights.Splice, d.aiBaseWeights.Insert,
			d.aiBaseWeights.MutateArg, d.aiBaseWeights.Remove, d.aiBaseWeights.Reorder)
	}
}

// --- Snapshot for dashboard and AI prompts ---

// DEzzerSnapshot is the serializable state for external consumption.
type DEzzerSnapshot struct {
	Generation   int                `json:"generation"`
	TotalRecords int64              `json:"total_records"`
	WarmupDone   bool               `json:"warmup_done"`
	Saturated    bool               `json:"saturated"`

	OpSuccessRates map[string]float64 `json:"op_success_rates"`
	OpAvgCovGain   map[string]float64 `json:"op_avg_cov_gain"`

	AIBaseWeights map[string]float64 `json:"ai_base_weights"`
	TSDelta       map[string]float64 `json:"ts_delta"`
	DECorrection  map[string]float64 `json:"de_correction"`
	FinalWeights  map[string]int     `json:"final_weights"`

	// Backward compat: DEDelta = TS×DE combined.
	DEDelta     map[string]float64 `json:"de_delta"`
	BestFitness float64            `json:"best_fitness"`

	// TS diagnostics.
	TSAlpha      map[string]float64 `json:"ts_alpha"`
	TSBeta       map[string]float64 `json:"ts_beta"`
	TSConfidence map[string]float64 `json:"ts_confidence"`

	// Phase 8b: Pair TS success rates.
	PairSuccessRates map[string]float64 `json:"pair_success_rates,omitempty"` // "prev->next" → rate

	// Phase 8e: Cluster TS summary.
	ClusterCounts map[string]int64 `json:"cluster_counts,omitempty"` // cluster_name → count

	// Phase 8c: Multi-objective status.
	CurrentObjective string         `json:"current_objective,omitempty"`
	ObjectiveCounts  map[string]int64 `json:"objective_counts,omitempty"`

	// Phase 11a: EMA + CUSUM diagnostics.
	EMARate     float64 `json:"ema_rate"`
	CUSUMHi    float64 `json:"cusum_hi"`
	CUSUMLo    float64 `json:"cusum_lo"`
	CUSUMResets int64  `json:"cusum_resets"`
}

func (d *DEzzer) Snapshot() DEzzerSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()

	snap := DEzzerSnapshot{
		Generation:     d.generation,
		TotalRecords:   d.totalRecords,
		WarmupDone:     d.warmupDone,
		Saturated:      d.saturated,
		BestFitness:    d.fitness[d.bestIdx],
		OpSuccessRates: make(map[string]float64),
		OpAvgCovGain:   make(map[string]float64),
		AIBaseWeights:  make(map[string]float64),
		TSDelta:        make(map[string]float64),
		DECorrection:   make(map[string]float64),
		FinalWeights:   make(map[string]int),
		DEDelta:        make(map[string]float64),
		TSAlpha:        make(map[string]float64),
		TSBeta:         make(map[string]float64),
		TSConfidence:   make(map[string]float64),
	}

	tsDelta := d.computeTSDelta()
	deCorr := d.population[d.bestIdx]
	defaults := prog.DefaultMutateOpts
	tsArr := vecToArr(tsDelta)
	deArr := vecToArr(deCorr)
	aiArr := vecToArr(d.aiBaseWeights)
	defaultWeights := [dezzerNumOps]int{
		defaults.SquashWeight, defaults.SpliceWeight, defaults.InsertWeight,
		defaults.MutateArgWeight, defaults.RemoveCallWeight, defaults.ReorderWeight,
	}

	for i, name := range opNames {
		sr, avg := d.opSuccessRate(i)
		snap.OpSuccessRates[name] = sr
		snap.OpAvgCovGain[name] = avg
		snap.AIBaseWeights[name] = aiArr[i]
		snap.TSDelta[name] = tsArr[i]
		snap.DECorrection[name] = deArr[i]
		snap.DEDelta[name] = tsArr[i] * deArr[i] // backward compat: combined
		snap.FinalWeights[name] = maxInt(1, int(float64(defaultWeights[i])*aiArr[i]*tsArr[i]*deArr[i]))
		snap.TSAlpha[name] = d.alpha[i]
		snap.TSBeta[name] = d.beta[i]
		snap.TSConfidence[name] = d.alpha[i] + d.beta[i]
	}

	// Phase 8b: Pair TS success rates.
	snap.PairSuccessRates = make(map[string]float64)
	for i := 0; i < dezzerNumOps; i++ {
		for j := 0; j < dezzerNumOps; j++ {
			if d.pairCount[i][j] > 0 {
				rate := d.pairAlpha[i][j] / (d.pairAlpha[i][j] + d.pairBeta[i][j])
				key := opNames[i] + "->" + opNames[j]
				snap.PairSuccessRates[key] = rate
			}
		}
	}

	// Phase 8e: Cluster counts.
	clusterNames := [numClusters]string{"fs", "net", "mm", "ipc", "device", "other", "io_uring", "bpf", "keyctl", "other2"}
	snap.ClusterCounts = make(map[string]int64)
	for c := 0; c < numClusters; c++ {
		if d.clusterCount[c] > 0 {
			snap.ClusterCounts[clusterNames[c]] = d.clusterCount[c]
		}
	}

	// Phase 8c: Multi-objective status.
	objNames := [NumObjectives]string{"coverage", "memory_safety", "priv_esc"}
	snap.CurrentObjective = objNames[d.currentObj]
	snap.ObjectiveCounts = make(map[string]int64)
	for i := 0; i < NumObjectives; i++ {
		snap.ObjectiveCounts[objNames[i]] = d.objCounts[i]
	}

	// Phase 11a: EMA + CUSUM diagnostics.
	snap.EMARate = d.emaRate
	snap.CUSUMHi = d.cusumHi
	snap.CUSUMLo = d.cusumLo
	snap.CUSUMResets = d.cusumResets

	return snap
}

// StatusString returns a human-readable DEzzer status for logging.
func (d *DEzzer) StatusString() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	tsDelta := d.computeTSDelta()
	deCorr := d.population[d.bestIdx]
	tsArr := vecToArr(tsDelta)
	deArr := vecToArr(deCorr)

	var parts []string
	for i, name := range opNames {
		sr, _ := d.opSuccessRate(i)
		parts = append(parts, fmt.Sprintf("%s=%.1f%%", name, sr*100))
	}

	return fmt.Sprintf("gen=%d TS={Sq:%.2f Sp:%.2f In:%.2f MA:%.2f Rm:%.2f Ro:%.2f} DE={Sq:%.3f Sp:%.3f In:%.3f MA:%.3f Rm:%.3f Ro:%.3f} rates=[%s]%s",
		d.generation,
		tsArr[0], tsArr[1], tsArr[2], tsArr[3], tsArr[4], tsArr[5],
		deArr[0], deArr[1], deArr[2], deArr[3], deArr[4], deArr[5],
		joinStrings(parts, ", "),
		d.statusSuffix())
}

// --- Thompson Sampling internals (caller must hold d.mu) ---

// computeTSDelta computes TS delta from posteriors.
// Normal mode: delta = prob/meanProb clamped to ±20%.
// Saturation mode: relative performance (prob/maxProb).
func (d *DEzzer) computeTSDelta() WeightVector {
	var probs [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		probs[i] = d.alpha[i] / (d.alpha[i] + d.beta[i])
	}

	// Saturation detection.
	meanProb := 0.0
	for _, p := range probs {
		meanProb += p
	}
	meanProb /= float64(dezzerNumOps)
	d.saturated = meanProb < dezzerSaturationThreshold

	var arr [dezzerNumOps]float64
	limit2 := d.getTSDeltaLimit() // Phase 12 C1: BO-tunable
	lo := 1.0 - limit2
	hi := 1.0 + limit2

	if d.saturated {
		// Saturation mode: relative performance (best operator = max delta).
		maxProb := 0.0
		for _, p := range probs {
			if p > maxProb {
				maxProb = p
			}
		}
		if maxProb < 1e-10 {
			maxProb = 1e-10
		}
		for i := 0; i < dezzerNumOps; i++ {
			relative := probs[i] / maxProb
			arr[i] = clampFloat(0.6+0.8*relative, lo, hi)
		}
	} else {
		// Normal mode: proportional to prob/meanProb.
		if meanProb < 1e-10 {
			meanProb = 1e-10
		}
		for i := 0; i < dezzerNumOps; i++ {
			arr[i] = clampFloat(probs[i]/meanProb, lo, hi)
		}
	}

	return arrToVec(arr)
}

// maybeDecay applies time-based exponential decay to TS posteriors.
// Phase 11a: Uses atomic timestamp to avoid time.Now() syscall in the fast path.
func (d *DEzzer) maybeDecay() {
	nowNano := time.Now().UnixNano()
	lastNano := d.lastDecayNano.Load()
	elapsedSec := float64(nowNano-lastNano) / 1e9
	if elapsedSec < float64(dezzerDecayIntervalSec) {
		return
	}

	intervals := int(elapsedSec / float64(dezzerDecayIntervalSec))
	factor := math.Pow(d.getDecayFactor(), float64(intervals)) // Phase 12 C1: BO-tunable
	for i := 0; i < dezzerNumOps; i++ {
		d.alpha[i] = math.Max(dezzerAlphaFloor, d.alpha[i]*factor)
		d.beta[i] = math.Max(dezzerBetaFloor, d.beta[i]*factor)
	}
	// Phase 8b: Decay pair TS.
	// Phase 12 A4: Per-layer decay gradient — pair uses factor^0.5 (slower than alpha/beta).
	pairFactor := math.Pow(factor, 0.5)
	for i := 0; i < dezzerNumOps; i++ {
		for j := 0; j < dezzerNumOps; j++ {
			d.pairAlpha[i][j] = math.Max(1.0, d.pairAlpha[i][j]*factor)
			d.pairBeta[i][j] = math.Max(1.0, d.pairBeta[i][j]*factor)
			// Phase 12 A4: Decay pairCount with slower factor, floor 50.
			newPC := int64(float64(d.pairCount[i][j]) * pairFactor)
			if newPC < dezzerPairMinData {
				newPC = dezzerPairMinData
			}
			if d.pairCount[i][j] > dezzerPairMinData {
				d.pairCount[i][j] = newPC
			}
		}
	}
	// Phase 8e: Decay cluster TS.
	// Phase 12 A4: Per-layer decay gradient — cluster uses factor^0.7.
	clusterFactor := math.Pow(factor, 0.7)
	for c := 0; c < numClusters; c++ {
		for i := 0; i < dezzerNumOps; i++ {
			d.clusterAlpha[c][i] = math.Max(1.0, d.clusterAlpha[c][i]*factor)
			d.clusterBeta[c][i] = math.Max(1.0, d.clusterBeta[c][i]*factor)
		}
		// Phase 12 A4: Decay clusterCount with slower factor, floor 100.
		newCC := int64(float64(d.clusterCount[c]) * clusterFactor)
		if newCC < 100 {
			newCC = 100
		}
		if d.clusterCount[c] > 100 {
			d.clusterCount[c] = newCC
		}
	}
	// Phase 12 B3: Decay cross-product TS with factor^0.3 (slowest — most sparse data).
	crossFactor := math.Pow(factor, 0.3)
	for c := 0; c < numClusters; c++ {
		for o := 0; o < NumObjectives; o++ {
			for i := 0; i < dezzerNumOps; i++ {
				d.crossAlpha[c][o][i] = math.Max(1.0, d.crossAlpha[c][o][i]*factor)
				d.crossBeta[c][o][i] = math.Max(1.0, d.crossBeta[c][o][i]*factor)
			}
			// crossCount decays with crossFactor (factor^0.3), floor 50.
			newXC := int64(float64(d.crossCount[c][o]) * crossFactor)
			if newXC < 50 {
				newXC = 50
			}
			if d.crossCount[c][o] > 50 {
				d.crossCount[c][o] = newXC
			}
		}
	}
	// Phase 12 B4: Decay sub-op TS with factor^0.4 (slow — sparse sub-op data).
	subFactor := math.Pow(factor, 0.4)
	for i := 0; i < dezzerNumOps; i++ {
		subs := subOpNames[opNames[i]]
		for j := 0; j < len(subs); j++ {
			d.subOpAlpha[i][j] = math.Max(1.0, d.subOpAlpha[i][j]*factor)
			d.subOpBeta[i][j] = math.Max(1.0, d.subOpBeta[i][j]*factor)
			newSC := int64(float64(d.subOpCount[i][j]) * subFactor)
			if newSC < 20 {
				newSC = 20
			}
			if d.subOpCount[i][j] > 20 {
				d.subOpCount[i][j] = newSC
			}
		}
	}

	// D23: Defense-in-depth alpha cap (closes CUSUM suppression window)
	for i := 0; i < dezzerNumOps; i++ {
		sum := d.alpha[i] + d.beta[i]
		if sum > 10000 {
			ratio := 1000.0 / sum
			d.alpha[i] *= ratio
			d.beta[i] *= ratio
		}
	}

	// D23: Apply same cap to cluster-level posteriors
	for c := 0; c < numClusters; c++ {
		for i := 0; i < dezzerNumOps; i++ {
			sum := d.clusterAlpha[c][i] + d.clusterBeta[c][i]
			if sum > 10000 {
				ratio := 1000.0 / sum
				d.clusterAlpha[c][i] *= ratio
				d.clusterBeta[c][i] *= ratio
			}
		}
	}

	d.lastDecayNano.Store(nowNano)
}

// StartNormalization runs a periodic goroutine (60s interval) that normalizes
// runaway TS posteriors. Phase 12 A5: Separate from maybeDecay to avoid lock doubling (HIGH-2).
// DO NOT normalize cross-product posteriors (CRIT-6).
// CUSUM mutual exclusion: suppress normalization for 60s after CUSUM reset (NEW-8).
func (d *DEzzer) StartNormalization(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.maybeNormalize()
			}
		}
	}()
}

// maybeNormalize checks and normalizes runaway alpha+beta posteriors.
// Threshold: 10000 → normalize to 1000 preserving ratio. Caller: periodic goroutine only.
func (d *DEzzer) maybeNormalize() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Phase 12 A5 NEW-8: Suppress normalization for 60s after CUSUM reset.
	if !d.lastCUSUMReset.IsZero() && time.Since(d.lastCUSUMReset) < 60*time.Second {
		return
	}

	const threshold = 10000.0
	const target = 1000.0
	normalized := false

	// Global alpha/beta normalization.
	for i := 0; i < dezzerNumOps; i++ {
		sum := d.alpha[i] + d.beta[i]
		if sum > threshold {
			ratio := target / sum
			d.alpha[i] *= ratio
			d.beta[i] *= ratio
			normalized = true
		}
	}

	// Pair alpha/beta normalization (same threshold).
	for i := 0; i < dezzerNumOps; i++ {
		for j := 0; j < dezzerNumOps; j++ {
			sum := d.pairAlpha[i][j] + d.pairBeta[i][j]
			if sum > threshold {
				ratio := target / sum
				d.pairAlpha[i][j] *= ratio
				d.pairBeta[i][j] *= ratio
				normalized = true
			}
		}
	}

	// Cluster alpha/beta normalization (same threshold).
	for c := 0; c < numClusters; c++ {
		for i := 0; i < dezzerNumOps; i++ {
			sum := d.clusterAlpha[c][i] + d.clusterBeta[c][i]
			if sum > threshold {
				ratio := target / sum
				d.clusterAlpha[c][i] *= ratio
				d.clusterBeta[c][i] *= ratio
				normalized = true
			}
		}
	}

	// NOTE: DO NOT normalize cross-product posteriors (B3, CRIT-6).
	// They naturally stay bounded by 108-way split + decay (~1390 steady-state).

	if normalized {
		d.lastNormalization = time.Now()
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer A5 normalization triggered (threshold=%.0f→target=%.0f)", threshold, target)
		}
	}
}

// pathWeight returns the feedback quality weight for the given source.
func (d *DEzzer) pathWeight(source FeedbackSource) float64 {
	switch source {
	case SourceSmash:
		return dezzerWeightSmash
	case SourceFocus:
		return dezzerWeightFocus
	default:
		return dezzerWeightMutate
	}
}

// ipwWeight returns inverse propensity weight to correct for selection bias.
// Rarely-selected operators get higher weight per observation.
// Phase 11a: Uses d.totalRecords directly instead of summing opStats.Count.
func (d *DEzzer) ipwWeight(opIdx int) float64 {
	if d.totalRecords == 0 {
		return 1.0
	}
	propensity := float64(d.opStats[opIdx].Count) / float64(d.totalRecords)
	if propensity < 0.05 {
		propensity = 0.05 // cap at 20x to prevent extreme weights
	}
	return math.Min(1.0/propensity, dezzerIPWCap)
}

// --- DE internals (caller must hold d.mu) ---

// recalcDEFitness uses INDEPENDENT data (raw sliding window, not TS posteriors).
// Fitness = negative squared error from ideal correction vector.
// ideal[op] = clamp(rate[op]/meanRate, 1±corrLimit)
func (d *DEzzer) recalcDEFitness() {
	var rates [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		rates[i], _ = d.opSuccessRate(i)
	}
	meanRate := 0.0
	for _, r := range rates {
		meanRate += r
	}
	meanRate /= float64(dezzerNumOps)

	corrLimit := d.activeCorrLimit()

	for p := range d.population {
		arr := vecToArr(d.population[p])
		fit := 0.0
		for i := 0; i < dezzerNumOps; i++ {
			ideal := 1.0
			if meanRate > 1e-10 {
				ideal = clampFloat(rates[i]/meanRate, 1.0-corrLimit, 1.0+corrLimit)
			}
			diff := arr[i] - ideal
			fit -= diff * diff
		}
		d.fitness[p] = fit
		if fit > d.fitness[d.bestIdx] {
			d.bestIdx = p
		}
	}
}

// checkConflict detects when TS and DE disagree on direction for ≥3/5 operators.
func (d *DEzzer) checkConflict() {
	tsDelta := d.computeTSDelta()
	deCorr := d.population[d.bestIdx]
	tsArr := vecToArr(tsDelta)
	deArr := vecToArr(deCorr)

	conflicts := 0
	for i := 0; i < dezzerNumOps; i++ {
		tsDir := tsArr[i] - 1.0
		deDir := deArr[i] - 1.0
		if (tsDir > 0.01 && deDir < -0.01) || (tsDir < -0.01 && deDir > 0.01) {
			conflicts++
		}
	}

	if conflicts >= dezzerConflictThreshold && !d.conflictDampened {
		d.conflictDampened = true
		d.dampenGensLeft = dezzerDampenRecoveryGen
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer TS/DE conflict (%d/%d), dampening DE to ±%.0f%%",
				conflicts, dezzerNumOps, dezzerDampenedCorrLimit*100)
		}
		// Re-clamp population to dampened range.
		for i := range d.population {
			d.population[i] = clampVectorRange(d.population[i], dezzerDampenedCorrLimit)
		}
	}
}

// --- Phase 11a: DE snapshot pattern (copy-evolve-apply outside lock) ---

// deEvolveSnapshot holds a frozen copy of DE state for lock-free evolution.
type deEvolveSnapshot struct {
	population [dezzerPopSize]WeightVector
	fitness    [dezzerPopSize]float64
	bestIdx    int
	generation int
	corrLimit  float64
	totalRec   int64
	rates      [dezzerNumOps]float64
	// conflict state
	conflictDampened bool
	dampenGensLeft   int
	stagnantGens     int
	lastBestCorr     WeightVector
}

// snapshotDEState copies DE state under the lock for evolution outside.
func (d *DEzzer) snapshotDEState() deEvolveSnapshot {
	snap := deEvolveSnapshot{
		population:       d.population,
		fitness:          d.fitness,
		bestIdx:          d.bestIdx,
		generation:       d.generation,
		corrLimit:        d.activeCorrLimit(),
		totalRec:         d.totalRecords,
		conflictDampened: d.conflictDampened,
		dampenGensLeft:   d.dampenGensLeft,
		stagnantGens:     d.stagnantGens,
		lastBestCorr:     d.lastBestCorr,
	}
	for i := 0; i < dezzerNumOps; i++ {
		snap.rates[i], _ = d.opSuccessRate(i)
	}
	return snap
}

// evolveDEOutsideLock runs one DE generation using a snapshot (no lock held).
func (d *DEzzer) evolveDEOutsideLock(snap deEvolveSnapshot) (
	[dezzerPopSize]WeightVector, [dezzerPopSize]float64, int, int,
) {
	pop := snap.population
	fit := snap.fitness
	bestIdx := snap.bestIdx
	corrLimit := snap.corrLimit
	generation := snap.generation

	// Conflict recovery countdown.
	dampened := snap.conflictDampened
	if dampened {
		snap.dampenGensLeft--
		if snap.dampenGensLeft <= 0 {
			dampened = false
			corrLimit = dezzerDECorrLimit
		}
	}

	rnd := rand.New(rand.NewSource(snap.totalRec + int64(generation)))

	meanRate := 0.0
	for _, r := range snap.rates {
		meanRate += r
	}
	meanRate /= float64(dezzerNumOps)

	// evalVec evaluates fitness for a vector using snapshot rates.
	evalVec := func(v WeightVector) float64 {
		arr := vecToArr(v)
		f := 0.0
		for i := 0; i < dezzerNumOps; i++ {
			ideal := 1.0
			if meanRate > 1e-10 {
				ideal = clampFloat(snap.rates[i]/meanRate, 1.0-corrLimit, 1.0+corrLimit)
			}
			diff := arr[i] - ideal
			f -= diff * diff
		}
		return f
	}

	for i := range pop {
		a, b, c := i, i, i
		for a == i {
			a = rnd.Intn(dezzerPopSize)
		}
		for b == i || b == a {
			b = rnd.Intn(dezzerPopSize)
		}
		for c == i || c == a || c == b {
			c = rnd.Intn(dezzerPopSize)
		}

		trial := d.deMutantVector(pop[a], pop[b], pop[c], rnd)
		trial = clampVectorRange(trial, corrLimit)
		trialFit := evalVec(trial)

		if trialFit >= fit[i] {
			pop[i] = trial
			fit[i] = trialFit
			if trialFit > fit[bestIdx] {
				bestIdx = i
			}
		}
	}

	generation++
	return pop, fit, bestIdx, generation
}

// applyDEResults writes back evolved DE state under the lock.
func (d *DEzzer) applyDEResults(
	pop [dezzerPopSize]WeightVector, fit [dezzerPopSize]float64,
	bestIdx, generation int,
) {
	d.population = pop
	d.fitness = fit
	d.bestIdx = bestIdx
	d.generation = generation

	// Conflict detection on new population.
	d.checkConflict()

	// Stagnation detection.
	best := d.population[d.bestIdx]
	if best == d.lastBestCorr {
		d.stagnantGens++
	} else {
		d.stagnantGens = 0
		d.lastBestCorr = best
	}
	if d.stagnantGens >= dezzerStagnantLimit {
		d.partialRestart(d.activeCorrLimit())
	}

	// Periodic logging.
	if d.logf != nil && d.generation%10 == 0 {
		tsDelta := d.computeTSDelta()
		deCorr := d.population[d.bestIdx]
		d.logf(0, "PROBE: DEzzer gen=%d TS={Sq:%.2f Sp:%.2f In:%.2f MA:%.2f Rm:%.2f Ro:%.2f} DE={Sq:%.3f Sp:%.3f In:%.3f MA:%.3f Rm:%.3f Ro:%.3f}%s",
			d.generation,
			tsDelta.Squash, tsDelta.Splice, tsDelta.Insert, tsDelta.MutateArg, tsDelta.Remove, tsDelta.Reorder,
			deCorr.Squash, deCorr.Splice, deCorr.Insert, deCorr.MutateArg, deCorr.Remove, deCorr.Reorder,
			d.statusSuffix())
	}
}

// --- Phase 11a: EMA + CUSUM change-point detection ---

// updateEMACUSUM tracks the exponential moving average of success rate
// and applies a two-sided CUSUM test for regime changes.
// On alarm, TS posteriors get a partial reset to accelerate adaptation.
// Circuit breaker: disables CUSUM for 10 minutes if >3 resets in a window.
// Caller must hold d.mu. Called every dezzerCUSUMSampleEvery records.
func (d *DEzzer) updateEMACUSUM(success bool) {
	// Phase 11l: Skip CUSUM during shadow pause (BO parameter transition).
	if !d.cusumShadowUntil.IsZero() && time.Now().Before(d.cusumShadowUntil) {
		d.updateCUSUMStats()
		return
	}

	now := time.Now()
	nowSec := now.Unix()

	// Circuit breaker: if disabled, check if cooldown has expired.
	if d.cusumDisabled {
		if now.Sub(d.cusumDisableTime).Seconds() < float64(dezzerCUSUMBreakerWinSec) {
			// Still in cooldown — only update stats, skip CUSUM logic.
			d.updateCUSUMStats()
			return
		}
		// Cooldown expired: re-enable CUSUM, full reset state.
		d.cusumDisabled = false
		d.cusumHi = 0
		d.cusumLo = 0
		d.cusumRecentResets = d.cusumRecentResets[:0]
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer CUSUM circuit breaker released, resuming detection")
		}
	}

	sample := 0.0
	if success {
		sample = 1.0
	}

	// Update EMA.
	d.emaRate = dezzerEMASmoothingAlpha*sample + (1.0-dezzerEMASmoothingAlpha)*d.emaRate

	// Two-sided CUSUM: detect both upward and downward shifts.
	d.cusumHi = math.Max(0, d.cusumHi+(sample-d.emaRate-dezzerCUSUMDrift))
	d.cusumLo = math.Max(0, d.cusumLo+(d.emaRate-sample-dezzerCUSUMDrift))

	// Check for alarm (regime change).
	// Phase 12 A5: Suppress CUSUM alarm for 60s after normalization (mutual exclusion).
	cusumSuppressed := !d.lastNormalization.IsZero() && now.Sub(d.lastNormalization) < 60*time.Second
	if !cusumSuppressed && (d.cusumHi > dezzerCUSUMThreshold || d.cusumLo > dezzerCUSUMThreshold) {
		d.cusumResets++
		d.lastCUSUMReset = now       // Phase 12 A5: record for mutual exclusion
		d.recordsSinceCUSUM = 0      // Phase 12 B1: reset regime-local counter
		// Phase 12 B3: Reset crossCount to force fresh learning after regime change.
		for c := 0; c < numClusters; c++ {
			for o := 0; o < NumObjectives; o++ {
				d.crossCount[c][o] = 0
			}
		}
		// Phase 12 B4: Reset sub-op counts on CUSUM regime change.
		for i := 0; i < dezzerNumOps; i++ {
			for j := 0; j < maxSubOps; j++ {
				d.subOpCount[i][j] = 0
			}
		}
		// Partial reset: keep 50% of TS posteriors to accelerate adaptation.
		for i := 0; i < dezzerNumOps; i++ {
			d.alpha[i] = dezzerAlphaFloor + 0.5*(d.alpha[i]-dezzerAlphaFloor)
			d.beta[i] = dezzerBetaFloor + 0.5*(d.beta[i]-dezzerBetaFloor)
		}
		// Full zero reset of CUSUM accumulators (prevents re-triggering cascade).
		d.cusumHi = 0
		d.cusumLo = 0

		// Track this reset timestamp for circuit breaker.
		d.cusumRecentResets = append(d.cusumRecentResets, nowSec)
		// Evict old entries outside the window.
		cutoff := nowSec - int64(dezzerCUSUMBreakerWinSec)
		trimIdx := 0
		for trimIdx < len(d.cusumRecentResets) && d.cusumRecentResets[trimIdx] < cutoff {
			trimIdx++
		}
		if trimIdx > 0 {
			d.cusumRecentResets = d.cusumRecentResets[trimIdx:]
		}

		// Circuit breaker: too many resets in window → disable CUSUM.
		if len(d.cusumRecentResets) > dezzerCUSUMMaxResetsWin {
			d.cusumDisabled = true
			d.cusumDisableTime = now
			if d.logf != nil {
				d.logf(0, "PROBE: DEzzer CUSUM circuit breaker tripped (%d resets in %ds window), disabling for %ds",
					len(d.cusumRecentResets), dezzerCUSUMBreakerWinSec, dezzerCUSUMBreakerWinSec)
			}
		} else if d.logf != nil {
			d.logf(0, "PROBE: DEzzer CUSUM regime change #%d detected (EMA=%.4f), TS partial reset",
				d.cusumResets, d.emaRate)
		}

		if d.statCusumResets != nil {
			d.statCusumResets.Add(1)
		}
	}

	d.updateCUSUMStats()
}

// updateCUSUMStats updates the stat gauges for dashboard reporting.
// Caller must hold d.mu.
func (d *DEzzer) updateCUSUMStats() {
	if d.statCusumValue != nil {
		cusumMax := math.Max(d.cusumHi, d.cusumLo)
		d.statCusumValue.Add(int(cusumMax*1000) - d.statCusumValue.Val())
	}
	if d.statEmaRate != nil {
		d.statEmaRate.Add(int(d.emaRate*10000) - d.statEmaRate.Val())
	}
}

// SetCUSUMStats sets the stat references for CUSUM metrics.
// Called by the fuzzer during initialization after stats are registered.
func (d *DEzzer) SetCUSUMStats(cusumResets, cusumValue, emaRate *stat.Val) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.statCusumResets = cusumResets
	d.statCusumValue = cusumValue
	d.statEmaRate = emaRate
}

// PauseCUSUM sets a shadow pause for CUSUM (prevents false alarms during BO transitions).
func (d *DEzzer) PauseCUSUM(duration time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cusumShadowUntil = time.Now().Add(duration)
	if d.logf != nil {
		d.logf(0, "PROBE: DEzzer CUSUM shadow pause for %v", duration)
	}
}

func (d *DEzzer) evalDEVector(v WeightVector, corrLimit float64) float64 {
	var rates [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		rates[i], _ = d.opSuccessRate(i)
	}
	meanRate := 0.0
	for _, r := range rates {
		meanRate += r
	}
	meanRate /= float64(dezzerNumOps)

	arr := vecToArr(v)
	fit := 0.0
	for i := 0; i < dezzerNumOps; i++ {
		ideal := 1.0
		if meanRate > 1e-10 {
			ideal = clampFloat(rates[i]/meanRate, 1.0-corrLimit, 1.0+corrLimit)
		}
		diff := arr[i] - ideal
		fit -= diff * diff
	}
	return fit
}

func (d *DEzzer) activeCorrLimit() float64 {
	if d.conflictDampened {
		return dezzerDampenedCorrLimit
	}
	return dezzerDECorrLimit
}

func (d *DEzzer) statusSuffix() string {
	suffix := ""
	if d.saturated {
		suffix += " [SATURATED]"
	}
	if d.conflictDampened {
		suffix += " [DAMPENED]"
	}
	if d.explorationMode {
		suffix += " [EXPLORING]"
	}
	return suffix
}

// partialRestart keeps the top dezzerKeepBest individuals and randomizes the rest.
func (d *DEzzer) partialRestart(corrLimit float64) {
	type idxFit struct {
		idx int
		fit float64
	}
	sorted := make([]idxFit, dezzerPopSize)
	for i := range d.population {
		sorted[i] = idxFit{i, d.fitness[i]}
	}
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].fit > sorted[i].fit {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	keep := make(map[int]bool)
	for i := 0; i < dezzerKeepBest && i < len(sorted); i++ {
		keep[sorted[i].idx] = true
	}

	rnd := rand.New(rand.NewSource(d.totalRecords + int64(d.generation)*7))
	for i := range d.population {
		if keep[i] {
			continue
		}
		d.population[i] = randomVector(rnd, corrLimit)
		d.fitness[i] = d.evalDEVector(d.population[i], corrLimit)
	}

	d.bestIdx = 0
	for i := 1; i < dezzerPopSize; i++ {
		if d.fitness[i] > d.fitness[d.bestIdx] {
			d.bestIdx = i
		}
	}
	d.stagnantGens = 0
	d.lastBestCorr = d.population[d.bestIdx]

	if d.logf != nil {
		best := d.population[d.bestIdx]
		d.logf(0, "PROBE: DEzzer DE partial restart (kept top %d) — gen=%d corr={Sq:%.3f Sp:%.3f In:%.3f MA:%.3f Rm:%.3f Ro:%.3f}",
			dezzerKeepBest, d.generation, best.Squash, best.Splice, best.Insert, best.MutateArg, best.Remove, best.Reorder)
	}
}

func (d *DEzzer) deMutantVector(a, b, c WeightVector, rnd *rand.Rand) WeightVector {
	jrand := rnd.Intn(dezzerNumOps)
	aArr := vecToArr(a)
	bArr := vecToArr(b)
	cArr := vecToArr(c)

	var result [dezzerNumOps]float64
	for j := 0; j < dezzerNumOps; j++ {
		if rnd.Float64() < dezzerCR || j == jrand {
			result[j] = aArr[j] + dezzerF*(bArr[j]-cArr[j])
		} else {
			result[j] = aArr[j]
		}
	}
	return arrToVec(result)
}

// --- Common helpers ---

func (d *DEzzer) opSuccessRate(opIdx int) (float64, float64) {
	stats := &d.opStats[opIdx]
	n := int(stats.Count)
	if n == 0 {
		return 0, 0
	}
	if n > dezzerWindowSize {
		n = dezzerWindowSize
	}
	successes := 0
	totalGain := 0
	for i := 0; i < n; i++ {
		r := stats.Window[i]
		if r.CovGainBits > 0 {
			successes++
		}
		totalGain += r.CovGainBits
	}
	return float64(successes) / float64(n), float64(totalGain) / float64(n)
}

// recordFeature writes to the feature ring buffer using an atomic counter.
// Phase 11a: No lock needed — uses atomic index for monotonic slot assignment.
// Phase 12 B1: Enriched with context fields (pre-computed under lock, passed as params).
func (d *DEzzer) recordFeature(opIdx int, covGain int, success bool, source FeedbackSource,
	cluster int, emaRate int, recordsSinceCUSUM int64, prevOpIdx int) {
	entropy := 0
	if d.entropyRef != nil {
		entropy = int(d.entropyRef.Load())
	}
	seq := d.featureLogIdx.Add(1) - 1
	slot := int(seq % int64(dezzerFeatureLogSize))
	d.featureLog[slot] = FeatureTuple{
		Timestamp:         seq, // monotonic record ID instead of wall-clock
		OpIdx:             opIdx,
		CovGain:           covGain,
		Success:           success,
		Source:            source,
		Saturated:         d.saturated,
		ProgramCluster:    cluster,
		CoverageEntropy:   entropy,
		EMARate:           emaRate,
		RecordsSinceCUSUM: recordsSinceCUSUM,
		PrevOp:            prevOpIdx,
		ConfigVersion:     d.configVersion,
	}
}

// --- Phase 12 B2: FeatureTuple export API ---

// ExportFeatures returns up to 100K tuples from the ring buffer, ordered by monotonic timestamp.
// Handles wrap-around correctly by snapshotting the atomic index.
func (d *DEzzer) ExportFeatures() []FeatureTuple {
	currentIdx := d.featureLogIdx.Load()
	if currentIdx == 0 {
		return nil
	}
	count := int(currentIdx)
	if count > dezzerFeatureLogSize {
		count = dezzerFeatureLogSize
	}
	result := make([]FeatureTuple, 0, count)
	startSeq := currentIdx - int64(count)
	for seq := startSeq; seq < currentIdx; seq++ {
		slot := int(seq % int64(dezzerFeatureLogSize))
		ft := d.featureLog[slot]
		if ft.Timestamp >= startSeq { // validate not overwritten
			result = append(result, ft)
		}
	}
	return result
}

// StartAutoExport starts a goroutine that appends ring buffer to CSV every 2 minutes.
// Phase 12 B2: Tracks last-exported seq to avoid duplicates. Auto-rotates at 10M rows.
func (d *DEzzer) StartAutoExport(ctx context.Context, workdir string) {
	if workdir == "" {
		return
	}
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		var lastExportedSeq int64
		var totalRows int64
		var fileIdx int

		csvPath := func() string {
			if fileIdx == 0 {
				return workdir + "/feature_log.csv"
			}
			return fmt.Sprintf("%s/feature_log_%d.csv", workdir, fileIdx)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				currentIdx := d.featureLogIdx.Load()
				if currentIdx <= lastExportedSeq {
					continue
				}
				// Determine range to export.
				startSeq := lastExportedSeq
				endSeq := currentIdx
				// Don't go further back than ring buffer size.
				if endSeq-startSeq > int64(dezzerFeatureLogSize) {
					startSeq = endSeq - int64(dezzerFeatureLogSize)
				}
				// Auto-rotate at 10M rows.
				if totalRows >= 10_000_000 {
					fileIdx++
					totalRows = 0
				}
				path := csvPath()
				f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					if d.logf != nil {
						d.logf(0, "PROBE: B2 auto-export failed to open %s: %v", path, err)
					}
					continue
				}
				w := csv.NewWriter(f)
				// Write header if new file.
				if totalRows == 0 {
					w.Write([]string{"seq", "op", "cov_gain", "success", "source", "saturated",
						"cluster", "entropy", "ema_rate", "records_since_cusum", "prev_op", "config_ver"})
				}
				var exported int64
				for seq := startSeq; seq < endSeq; seq++ {
					slot := int(seq % int64(dezzerFeatureLogSize))
					ft := d.featureLog[slot]
					if ft.Timestamp < startSeq {
						continue // stale entry
					}
					successStr := "0"
					if ft.Success {
						successStr = "1"
					}
					satStr := "0"
					if ft.Saturated {
						satStr = "1"
					}
					w.Write([]string{
						strconv.FormatInt(ft.Timestamp, 10),
						strconv.Itoa(ft.OpIdx),
						strconv.Itoa(ft.CovGain),
						successStr,
						strconv.Itoa(int(ft.Source)),
						satStr,
						strconv.Itoa(ft.ProgramCluster),
						strconv.Itoa(ft.CoverageEntropy),
						strconv.Itoa(ft.EMARate),
						strconv.FormatInt(ft.RecordsSinceCUSUM, 10),
						strconv.Itoa(ft.PrevOp),
						strconv.Itoa(ft.ConfigVersion),
					})
					exported++
				}
				w.Flush()
				f.Close()
				totalRows += exported
				lastExportedSeq = endSeq
				if d.logf != nil && exported > 0 {
					d.logf(1, "PROBE: B2 auto-exported %d features to %s (total=%d)", exported, path, totalRows)
				}
			}
		}
	}()
}

// --- Phase 8c: Multi-objective meta-bandit ---

// selectObjective uses UCB-1 to choose the next objective.
func (d *DEzzer) selectObjective() int {
	totalPulls := int64(0)
	for _, c := range d.objCounts {
		totalPulls += c
	}

	// Ensure each objective is tried at least once.
	for i := 0; i < NumObjectives; i++ {
		if d.objCounts[i] == 0 {
			return i
		}
	}

	// Dynamic coverage floor: coverage must get at least this fraction of selection.
	hours := time.Since(d.startTime).Hours()
	covFloor := objCovFloorInit
	if hours > 4 {
		covFloor = objCovFloorLate
	} else if hours > 1 {
		covFloor = objCovFloorMid
	}

	// If coverage is under-selected, force it.
	covFrac := float64(d.objCounts[ObjCoverage]) / float64(totalPulls)
	if covFrac < covFloor {
		return ObjCoverage
	}

	// UCB-1: argmax(reward/count + sqrt(2*ln(totalCount)/count))
	bestObj := 0
	bestScore := -1.0
	lnTotal := math.Log(float64(totalPulls))
	for i := 0; i < NumObjectives; i++ {
		avgReward := d.objRewards[i] / float64(d.objCounts[i])
		exploration := math.Sqrt(2.0 * lnTotal / float64(d.objCounts[i]))
		score := avgReward + exploration
		if score > bestScore {
			bestScore = score
			bestObj = i
		}
	}

	if d.logf != nil {
		objNames := [NumObjectives]string{"coverage", "memory_safety", "priv_esc"}
		d.logf(2, "PROBE: DEzzer objective selected: %s (counts: cov=%d mem=%d priv=%d)",
			objNames[bestObj], d.objCounts[ObjCoverage], d.objCounts[ObjMemorySafety], d.objCounts[ObjPrivEsc])
	}
	return bestObj
}

// RecordObjectiveReward records a reward for the current objective.
func (d *DEzzer) RecordObjectiveReward(reward float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.currentObj >= 0 && d.currentObj < NumObjectives {
		d.objRewards[d.currentObj] += reward
		d.objCounts[d.currentObj]++
	}
}

// CurrentObjective returns the currently active objective (lock-free via atomic cache).
func (d *DEzzer) CurrentObjective() int {
	return int(d.currentObjCache.Load())
}

// --- Utility functions ---

func randomVector(rnd *rand.Rand, limit float64) WeightVector {
	return WeightVector{
		Squash:    1.0 + (rnd.Float64()-0.5)*2*limit,
		Splice:    1.0 + (rnd.Float64()-0.5)*2*limit,
		Insert:    1.0 + (rnd.Float64()-0.5)*2*limit,
		MutateArg: 1.0 + (rnd.Float64()-0.5)*2*limit,
		Remove:    1.0 + (rnd.Float64()-0.5)*2*limit,
		Reorder:   1.0 + (rnd.Float64()-0.5)*2*limit,
	}
}

func vecToArr(v WeightVector) [dezzerNumOps]float64 {
	return [dezzerNumOps]float64{v.Squash, v.Splice, v.Insert, v.MutateArg, v.Remove, v.Reorder}
}

func arrToVec(a [dezzerNumOps]float64) WeightVector {
	return WeightVector{a[0], a[1], a[2], a[3], a[4], a[5]}
}

func clampVectorRange(v WeightVector, limit float64) WeightVector {
	lo := 1.0 - limit
	hi := 1.0 + limit
	v.Squash = clampFloat(v.Squash, lo, hi)
	v.Splice = clampFloat(v.Splice, lo, hi)
	v.Insert = clampFloat(v.Insert, lo, hi)
	v.MutateArg = clampFloat(v.MutateArg, lo, hi)
	v.Remove = clampFloat(v.Remove, lo, hi)
	v.Reorder = clampFloat(v.Reorder, lo, hi)
	return v
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func safeDiv(a, b float64) float64 {
	if b == 0 || math.IsNaN(b) {
		return 1.0
	}
	r := a / b
	if math.IsNaN(r) || math.IsInf(r, 0) {
		return 1.0
	}
	return r
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}
