// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 11j — LinUCB contextual bandit for delay pattern selection.
// Completely separate from DEzzer (no shared state).
//
// Arms (4 delay patterns):
//   0 = DelayNone      — no delay injection
//   1 = DelayRandom    — random delays on random calls
//   2 = DelayBetween   — uniform delay between all calls
//   3 = DelayAroundLocks — targeted delay near lock-related syscalls
//
// Feature vector (d=8):
//   [prog_len, lock_syscall_ratio, ebpf_contention, ebpf_concurrent,
//    sched_switches, coverage_delta, prog_category, is_focus]
package fuzzer

import (
	"math"
	"sync"
)

const (
	linucbArms     = 4  // number of delay pattern arms
	linucbDim      = 8  // feature vector dimension
	linucbAlphaMax = 0.5
	linucbAlphaMin = 0.1
	linucbAnnealN  = 100000 // observations until alpha reaches min
)

// LinUCB implements the LinUCB contextual bandit algorithm for delay pattern selection.
type LinUCB struct {
	mu       sync.Mutex
	A        [linucbArms][][]float64 // d x d matrix per arm
	Ainv     [linucbArms][][]float64 // A^{-1} per arm (Sherman-Morrison incremental)
	b        [linucbArms][]float64   // d x 1 per arm
	alpha    float64                 // exploration coefficient (annealing)
	totalObs int64                   // total observations for annealing
	armPicks [linucbArms]int64       // arm selection counts for diagnostics
	logf     func(level int, msg string, args ...any)

	// Convergence cache: when one arm dominates (99%+), skip matrix computation.
	cachedArm  int
	cacheValid bool
	cacheUntil int64 // totalObs threshold; cache valid while totalObs < cacheUntil
}

// NewLinUCB creates a new LinUCB contextual bandit with identity-initialized matrices.
func NewLinUCB() *LinUCB {
	l := &LinUCB{
		alpha: linucbAlphaMax,
	}
	for a := 0; a < linucbArms; a++ {
		l.A[a] = identityMatrix(linucbDim)
		l.Ainv[a] = identityMatrix(linucbDim)
		l.b[a] = make([]float64, linucbDim)
	}
	return l
}

// SelectArm selects the best delay pattern arm given context features.
// UCB: p_a = theta_a^T x + alpha * sqrt(x^T A_a^{-1} x), return argmax.
func (l *LinUCB) SelectArm(features []float64) int {
	if len(features) != linucbDim {
		return 0 // default: no delay
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Copy features to fixed-size array to avoid heap allocations.
	var featArr [linucbDim]float64
	copy(featArr[:], features)

	// Forced exploration FIRST: ensure each arm is tried at least 100 times.
	// Must run before cache check — otherwise cache locks out under-explored arms.
	for a := 0; a < linucbArms; a++ {
		if l.armPicks[a] < 100 {
			return a
		}
	}

	// Convergence cache: skip matrix computation if one arm dominates.
	if l.cacheValid && l.totalObs < l.cacheUntil {
		return l.cachedArm
	}

	bestArm := 0
	bestScore := math.Inf(-1)

	for a := 0; a < linucbArms; a++ {
		// theta_a = A_a^{-1} * b_a
		theta := matVecMul(l.Ainv[a], l.b[a])
		// exploitation: theta_a^T * x
		exploit := dotProductArr(theta, featArr)
		// exploration: alpha * sqrt(x^T * A_a^{-1} * x)
		Ainvx := matVecMul(l.Ainv[a], features)
		explore := l.alpha * math.Sqrt(math.Max(0, dotProduct(features, Ainvx)))
		score := exploit + explore
		if score > bestScore+1e-9 {
			bestScore = score
			bestArm = a
		} else if math.Abs(score-bestScore) < 1e-9 && l.armPicks[a] < l.armPicks[bestArm] {
			// Tie-break: prefer less-explored arm to avoid index-0 bias.
			bestScore = score
			bestArm = a
		}
	}

	return bestArm
}

// Update updates the LinUCB model for the chosen arm with observed reward.
// Uses Sherman-Morrison incremental inverse update:
//   A_a^{-1} = A_a^{-1} - (A_a^{-1} x x^T A_a^{-1}) / (1 + x^T A_a^{-1} x)
func (l *LinUCB) Update(arm int, features []float64, reward float64) {
	if arm < 0 || arm >= linucbArms || len(features) != linucbDim {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// b_a = b_a + reward * x (always needed).
	for i := 0; i < linucbDim; i++ {
		l.b[arm][i] += reward * features[i]
	}

	// Sherman-Morrison update for A_a^{-1}: skip when convergence cache is active.
	if !(l.cacheValid && l.totalObs < l.cacheUntil) {
		Ainv := l.Ainv[arm]
		AinvxArr := matVecMul(Ainv, features)
		denom := 1.0 + dotProduct(features, AinvxArr)
		if denom < 1e-10 {
			denom = 1e-10
		}
		for i := 0; i < linucbDim; i++ {
			for j := 0; j < linucbDim; j++ {
				Ainv[i][j] -= (AinvxArr[i] * AinvxArr[j]) / denom
			}
		}
	}

	l.totalObs++
	l.armPicks[arm]++
	ratio := float64(l.totalObs) / float64(linucbAnnealN)
	if ratio > 1.0 {
		ratio = 1.0
	}
	l.alpha = math.Max(linucbAlphaMin, linucbAlphaMax*(1.0-ratio))

	// Convergence detection: only cache AFTER annealing AND forced exploration complete.
	// All arms must have >= 100 picks before caching is allowed.
	if l.totalObs > linucbAnnealN {
		allExplored := true
		for a := 0; a < linucbArms; a++ {
			if l.armPicks[a] < 100 {
				allExplored = false
				break
			}
		}
		if allExplored {
			for a := 0; a < linucbArms; a++ {
				if l.armPicks[a]*1000 > l.totalObs*995 {
					l.cachedArm = a
					l.cacheValid = true
					l.cacheUntil = l.totalObs + 5000
					break
				}
			}
		}
	}

	// Diagnostic log every 1000 observations.
	if l.logf != nil && l.totalObs%1000 == 0 {
		cached := ""
		if l.cacheValid && l.totalObs < l.cacheUntil {
			cached = " [CACHED]"
		}
		l.logf(0, "PROBE: LinUCB status: obs=%d, alpha=%.3f, arms=[None:%d Rand:%d Between:%d Locks:%d], reward=%.3f%s",
			l.totalObs, l.alpha,
			l.armPicks[0], l.armPicks[1], l.armPicks[2], l.armPicks[3],
			reward, cached)
	}
}

// SetAlpha overrides the LinUCB exploration parameter. Phase 12 C1: BO-tunable.
func (l *LinUCB) SetAlpha(alpha float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.alpha = math.Max(linucbAlphaMin, math.Min(alpha, 3.0))
}

// --- Linear algebra helpers ---

func identityMatrix(n int) [][]float64 {
	m := make([][]float64, n)
	for i := 0; i < n; i++ {
		m[i] = make([]float64, n)
		m[i][i] = 1.0
	}
	return m
}

func matVecMul(mat [][]float64, vec []float64) [linucbDim]float64 {
	var result [linucbDim]float64
	for i := 0; i < linucbDim; i++ {
		s := 0.0
		for j := 0; j < linucbDim; j++ {
			s += mat[i][j] * vec[j]
		}
		result[i] = s
	}
	return result
}

func dotProduct(a []float64, b [linucbDim]float64) float64 {
	s := 0.0
	for i := 0; i < linucbDim; i++ {
		s += a[i] * b[i]
	}
	return s
}

func dotProductArr(a, b [linucbDim]float64) float64 {
	s := 0.0
	for i := 0; i < linucbDim; i++ {
		s += a[i] * b[i]
	}
	return s
}
