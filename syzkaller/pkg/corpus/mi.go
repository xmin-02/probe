// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/stat"
)

const (
	miSampleSize     = 500
	miUpdateInterval = 5 * time.Minute
	miEarlyInterval  = 2 * time.Minute
	miEarlyDuration  = 1 * time.Hour
	miBlendWeight    = 0.3 // MI weight in blended score (0.7 coverage + 0.3 MI)
)

// MIScorer calculates mutual information scores for corpus programs.
// Programs with rare coverage edges receive higher scores, directing
// mutation budget toward seeds that provide unique coverage information.
type MIScorer struct {
	mu        sync.RWMutex
	scores    map[string]float64 // program hash -> normalized MI score [0,1]
	startTime time.Time
	lastCalc  time.Time

	statCalcCount *stat.Val
	statAvgScore  *stat.Val
}

func newMIScorer() *MIScorer {
	mi := &MIScorer{
		scores:    make(map[string]float64),
		startTime: time.Now(),
	}
	mi.statCalcCount = stat.New("mi recalcs", "Number of MI score recalculations",
		stat.Graph("mi"))
	mi.statAvgScore = stat.New("mi avg score", "Average MI score across corpus",
		stat.Graph("mi"), func() int {
			mi.mu.RLock()
			defer mi.mu.RUnlock()
			if len(mi.scores) == 0 {
				return 0
			}
			sum := 0.0
			for _, s := range mi.scores {
				sum += s
			}
			return int(sum / float64(len(mi.scores)) * 1000)
		})
	return mi
}

// calcMI performs MI calculation on a sample of corpus programs.
// It takes RLock on corpus, copies the needed data, releases lock, then computes off-lock.
func (mi *MIScorer) calcMI(corpus *Corpus) {
	// Step 1: Under RLock, snapshot program hashes and their signal elements.
	type progInfo struct {
		hash  string
		edges []uint64
	}

	corpus.mu.RLock()
	n := len(corpus.progsMap)
	if n == 0 {
		corpus.mu.RUnlock()
		return
	}

	// Collect all programs.
	allProgs := make([]progInfo, 0, n)
	for hash, item := range corpus.progsMap {
		edges := make([]uint64, 0, len(item.Signal))
		for e := range item.Signal {
			edges = append(edges, uint64(e))
		}
		allProgs = append(allProgs, progInfo{hash: hash, edges: edges})
	}
	corpus.mu.RUnlock()

	// Step 2: Sample programs (off-lock).
	sampleSize := miSampleSize
	if n < sampleSize {
		sampleSize = n
	}

	// Fisher-Yates partial shuffle for sampling.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < sampleSize; i++ {
		j := i + rng.Intn(n-i)
		allProgs[i], allProgs[j] = allProgs[j], allProgs[i]
	}
	sample := allProgs[:sampleSize]

	// Step 3: Compute per-edge frequency across the sample.
	edgeCount := make(map[uint64]int)
	for _, p := range sample {
		for _, e := range p.edges {
			edgeCount[e]++
		}
	}

	// Step 4: For each program, MI score = sum(-log2(freq[e]/sampleSize)) for each edge.
	rawScores := make(map[string]float64, sampleSize)
	maxScore := 0.0
	fSample := float64(sampleSize)
	for _, p := range sample {
		score := 0.0
		for _, e := range p.edges {
			freq := float64(edgeCount[e]) / fSample
			if freq > 0 {
				score += -math.Log2(freq)
			}
		}
		rawScores[p.hash] = score
		if score > maxScore {
			maxScore = score
		}
	}

	// Step 5: Normalize scores to [0, 1].
	if maxScore > 0 {
		for h := range rawScores {
			rawScores[h] /= maxScore
		}
	}

	// Step 6: Store results.
	mi.mu.Lock()
	mi.scores = rawScores
	mi.lastCalc = time.Now()
	mi.mu.Unlock()

	mi.statCalcCount.Add(1)
}

// getScore returns the MI score for a program, or 0 if not yet scored.
func (mi *MIScorer) getScore(progHash string) float64 {
	mi.mu.RLock()
	defer mi.mu.RUnlock()
	return mi.scores[progHash]
}

// shouldRecalc checks if it's time to recalculate MI scores.
func (mi *MIScorer) shouldRecalc() bool {
	mi.mu.RLock()
	last := mi.lastCalc
	mi.mu.RUnlock()

	if last.IsZero() {
		return true
	}
	interval := miUpdateInterval
	if time.Since(mi.startTime) < miEarlyDuration {
		interval = miEarlyInterval
	}
	return time.Since(last) >= interval
}

// runUpdater periodically recalculates MI scores until the context is cancelled.
func (mi *MIScorer) runUpdater(ctx context.Context, corpus *Corpus) {
	// Initial delay: wait for corpus to accumulate some programs.
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if mi.shouldRecalc() {
				mi.calcMI(corpus)
			}
		}
	}
}
