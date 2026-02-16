// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math"
	"math/rand"
	"sync"
)

// Schedule strategy arms for Global Thompson Sampling.
const (
	SchedNone      = 0 // no schedule perturbation
	SchedDelayOnly = 1 // delay injection only (ACTOR)
	SchedYieldOnly = 2 // sched_yield only (OZZ)
	SchedBoth      = 3 // delay + sched_yield combined
	SchedNumArms   = 4
)

// SchedTS implements Global Thompson Sampling for schedule strategy selection.
// Prior: heavy towards SchedNone (safe default), lighter on combined strategies.
type SchedTS struct {
	mu    sync.Mutex
	alpha [SchedNumArms]float64
	beta  [SchedNumArms]float64
	total int64
}

// NewSchedTS creates a new Global TS with informative priors.
// Priors express conservative preference: none=70%, delay=15%, yield=10%, both=5%.
func NewSchedTS() *SchedTS {
	s := &SchedTS{}
	// Informative priors (scaled to sum ~20 for moderate confidence):
	// SchedNone: 14/6 -> mean=0.70
	// SchedDelayOnly: 3/17 -> mean=0.15
	// SchedYieldOnly: 2/18 -> mean=0.10
	// SchedBoth: 1/19 -> mean=0.05
	s.alpha = [SchedNumArms]float64{14, 3, 2, 1}
	s.beta = [SchedNumArms]float64{6, 17, 18, 19}
	return s
}

// SelectArm samples from Beta posteriors and returns the arm with highest sample.
func (s *SchedTS) SelectArm(rnd *rand.Rand) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	bestArm := 0
	bestSample := -1.0

	for a := 0; a < SchedNumArms; a++ {
		sample := betaSample(rnd, s.alpha[a], s.beta[a])
		if sample > bestSample {
			bestSample = sample
			bestArm = a
		}
	}

	return bestArm
}

// Update records a reward for the selected arm.
// reward should be in [0, 1]: 1 = new coverage found, 0 = no new coverage.
func (s *SchedTS) Update(arm int, reward float64) {
	if arm < 0 || arm >= SchedNumArms {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.total++
	if reward > 0 {
		s.alpha[arm] += reward
	} else {
		s.beta[arm] += 1.0
	}

	// Slow decay every 500 observations to keep posteriors responsive.
	if s.total%500 == 0 {
		for a := 0; a < SchedNumArms; a++ {
			s.alpha[a] = math.Max(1.0, s.alpha[a]*0.95)
			s.beta[a] = math.Max(1.0, s.beta[a]*0.95)
		}
	}
}

// GetProbs returns current posterior mean probabilities for each arm.
func (s *SchedTS) GetProbs() [SchedNumArms]float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	var probs [SchedNumArms]float64
	for a := 0; a < SchedNumArms; a++ {
		probs[a] = s.alpha[a] / (s.alpha[a] + s.beta[a])
	}
	return probs
}

// betaSample samples from Beta(alpha, beta) using the Gamma function method.
func betaSample(rnd *rand.Rand, alpha, beta float64) float64 {
	x := gammaSample(rnd, alpha)
	y := gammaSample(rnd, beta)
	if x+y == 0 {
		return 0.5
	}
	return x / (x + y)
}

// gammaSample samples from Gamma(alpha, 1) using Marsaglia-Tsang method.
func gammaSample(rnd *rand.Rand, alpha float64) float64 {
	if alpha < 1 {
		// Boost method: Gamma(alpha) = Gamma(alpha+1) * U^(1/alpha)
		return gammaSample(rnd, alpha+1) * math.Pow(rnd.Float64(), 1.0/alpha)
	}
	d := alpha - 1.0/3.0
	c := 1.0 / math.Sqrt(9.0*d)
	for {
		var x, v float64
		for {
			x = rnd.NormFloat64()
			v = 1.0 + c*x
			if v > 0 {
				break
			}
		}
		v = v * v * v
		u := rnd.Float64()
		if u < 1.0-0.0331*(x*x)*(x*x) {
			return d * v
		}
		if math.Log(u) < 0.5*x*x+d*(1.0-v+math.Log(v)) {
			return d * v
		}
	}
}
